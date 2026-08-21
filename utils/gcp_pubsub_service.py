#!/usr/bin/env python
# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import json
import logging
import os
import re
import sys
import tempfile
import warnings
from logging import handlers
from typing import Any, Dict, Tuple

# Mute Google Cloud's Python version support warning for Python 3.10
warnings.filterwarnings("ignore", category=FutureWarning, module="google.api_core")

sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.gcp import download_from_gcs
from lib.cuckoo.common.path_utils import path_exists, path_mkdir
from lib.cuckoo.core.database import Database, init_database
from lib.cuckoo.core.startup import check_user_permissions
from utils.submit import submit_file

check_user_permissions(os.getenv("CAPE_AS_ROOT", False))

class ColoredFormatter(logging.Formatter):
    GREY = "\x1b[38;20m"
    GREEN = "\x1b[32;20m"
    YELLOW = "\x1b[33;20m"
    RED = "\x1b[31;20m"
    BOLD_RED = "\x1b[31;1m"
    CYAN = "\x1b[36;20m"
    RESET = "\x1b[0m"

    # Pre-compiled regex patterns (C-level high-performance parsing)
    RE_WORKER = re.compile(r"\b(cape-worker[-\w]*)\b", re.IGNORECASE)
    RE_SETSTAT = re.compile(r"\b(task)\b\s+(\d+)\s+(status)", re.IGNORECASE)
    RE_MAIN_TASK = re.compile(r"\b(main(?:_task)?_id|main|analysis(?:[\s_-]?id)?|cape(?:[\s_-]?id)?)\b[:\s=]+([\d,]+)", re.IGNORECASE)
    RE_WORKER_TASK = re.compile(r"\b(task(?:s|\(s\))?|task_id|worker(?:[\s_-]?id)?)\b[:\s=]+([\d,]+)", re.IGNORECASE)
    RE_PERF = re.compile(r"\bin\s+([0-9.]+s)\b")

    FORMATS = {
        logging.DEBUG: f"%(asctime)s [{CYAN}%(levelname)-7s{RESET}] %(name)s: %(message)s",
        logging.INFO: f"%(asctime)s [{GREEN}%(levelname)-7s{RESET}] %(name)s: %(message)s",
        logging.WARNING: f"%(asctime)s [{YELLOW}%(levelname)-7s{RESET}] %(name)s: %(message)s",
        logging.ERROR: f"%(asctime)s [{RED}%(levelname)-7s{RESET}] %(name)s: %(message)s",
        logging.CRITICAL: f"%(asctime)s [{BOLD_RED}%(levelname)-7s{RESET}] %(name)s: %(message)s",
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno, "%(asctime)s [%(levelname)-7s] %(name)s: %(message)s")
        formatter = logging.Formatter(log_fmt)
        formatted_message = formatter.format(record)

        # ANSI Colors
        BOLD_CYAN = "\x1b[36;1m"
        BOLD_GREEN = "\x1b[32;1m"
        BOLD_YELLOW = "\x1b[33;1m"
        BOLD_MAGENTA = "\x1b[35;1m"
        BOLD_BLUE = "\x1b[34;1m"
        BOLD_RED = "\x1b[31;1m"
        CYAN = "\x1b[36m"
        GREEN = "\x1b[32m"
        YELLOW = "\x1b[33m"
        MAGENTA = "\x1b[35m"
        RESET = "\x1b[0m"

        # 1. Highlight all worker/node names dynamically (e.g. "cape-worker", "cape-worker-2")
        formatted_message = self.RE_WORKER.sub(
            rf"{CYAN}\1{RESET}",
            formatted_message
        )

        # 2. Highlight specialized parent/main task updates first (e.g. "task 3319058 status")
        formatted_message = self.RE_SETSTAT.sub(
            rf"\1 {MAGENTA}\2{RESET} \3",
            formatted_message
        )

        # 3. Highlight parent/main task IDs (e.g. "Main ID: 3319058", "Main: 3319058", "main_task_id=3319058", "analysis ID 3319058", "analysis 3319058")
        formatted_message = self.RE_MAIN_TASK.sub(
            rf"\1: {MAGENTA}\2{RESET}",
            formatted_message
        )

        # 4. Highlight general task IDs (e.g. "Task: 16399266", "Task(s): 614534,614541", "task_id=495972")
        formatted_message = self.RE_WORKER_TASK.sub(
            rf"\1: {YELLOW}\2{RESET}",
            formatted_message
        )

        # 5. Highlight performance copy benchmarks (e.g. "in 0.08s", "in 0.15s")
        formatted_message = self.RE_PERF.sub(
            rf"in {GREEN}\1{RESET}",
            formatted_message
        )

        # 6. Highlight core operations
        replacements = {
            "[FETCH ]": f"{BOLD_GREEN}[FETCH ]{RESET}",
            "[SUBMIT]": f"{BOLD_CYAN}[SUBMIT]{RESET}",
            "[REMOVE]": f"{BOLD_RED}[REMOVE]{RESET}",
            "[GCS   ]": f"{BOLD_MAGENTA}[GCS   ]{RESET}",
            "[PERF  ]": f"{BOLD_YELLOW}[PERF  ]{RESET}",
        }

        for old, new in replacements.items():
            if old in formatted_message:
                formatted_message = formatted_message.replace(old, new)

        # 7. Highlight Status Metrics
        if "STATUS | " in formatted_message:
            formatted_message = formatted_message.replace("STATUS |", f"{BOLD_BLUE}STATUS{RESET} |")
            formatted_message = formatted_message.replace("Pend:", f"{BOLD_YELLOW}Pend:{RESET}")
            formatted_message = formatted_message.replace("Run:", f"{BOLD_GREEN}Run:{RESET}")
            formatted_message = formatted_message.replace("Done:", f"{BOLD_BLUE}Done:{RESET}")
            formatted_message = formatted_message.replace("Rep:", f"{BOLD_MAGENTA}Rep:{RESET}")

        return formatted_message


def init_logging(debug=False):
    formatter = logging.Formatter("%(asctime)s [%(levelname)-7s] %(name)s: %(message)s")
    log_obj = logging.getLogger("gcp_pubsub_service")
    log_obj.propagate = False  # Avoid duplicates with root logger

    for h in log_obj.handlers[:]:
        if isinstance(h, logging.StreamHandler) and h.stream == sys.stderr:
            log_obj.removeHandler(h)
            h.close()

    if not path_exists(os.path.join(CUCKOO_ROOT, "log")):
        path_mkdir(os.path.join(CUCKOO_ROOT, "log"))

    fh = handlers.TimedRotatingFileHandler(os.path.join(CUCKOO_ROOT, "log", "gcp_pubsub.log"), when="midnight", backupCount=10)
    fh.setFormatter(formatter)
    log_obj.addHandler(fh)

    handler_stdout = logging.StreamHandler(sys.stdout)
    handler_stdout.setFormatter(ColoredFormatter())
    log_obj.addHandler(handler_stdout)

    if debug:
        log_obj.setLevel(logging.DEBUG)
    else:
        log_obj.setLevel(logging.INFO)

    return log_obj


log = init_logging(os.getenv("DEBUG") == "True")

class GCPServiceLogger(logging.LoggerAdapter):
    def process(self, msg: str, kwargs: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        correlation_id = self.extra.get("correlation_id")
        if correlation_id:
            msg = f"[{correlation_id}] {msg}"
        return msg, kwargs

class GCPPubSubService:
    def __init__(self):
        import threading
        from lib.cuckoo.common.gcp import gcp_cfg
        self.processing_ids = set()
        self.ids_lock = threading.Lock()
        self.project_id = gcp_cfg.gcp.get("project")
        self.subscription_id = os.getenv("GCP_SUBSCRIPTION_ID") or (gcp_cfg.samples_pubsub.get("subscription_id") if hasattr(gcp_cfg, "samples_pubsub") else None)
        self.samples_bucket = (gcp_cfg.samples_pubsub.get("samples_bucket", "sandbox-samples-unique") if hasattr(gcp_cfg, "samples_pubsub") else "sandbox-samples-unique")

        if not self.project_id:
            # Fallback to env var if project is missing from config
            self.project_id = os.getenv("GOOGLE_CLOUD_PROJECT") or os.getenv("GCLOUD_PROJECT")

        if not self.project_id:
            log.error("GCP project ID not configured. Please set it in conf/gcp.conf")
            sys.exit(1)

        if not self.subscription_id:
            log.error("GCP subscription ID not configured. Please set it in conf/gcp.conf")
            sys.exit(1)

        # Ensure project ID is available for all GCP client libraries
        if not os.environ.get("GOOGLE_CLOUD_PROJECT"):
            os.environ["GOOGLE_CLOUD_PROJECT"] = self.project_id
        if not os.environ.get("GCLOUD_PROJECT"):
            os.environ["GCLOUD_PROJECT"] = self.project_id

        try:
            from google.cloud import pubsub_v1
            from google.cloud import storage
            self.pubsub_v1 = pubsub_v1

            auth_by = gcp_cfg.gcp.get("auth_by", "vm")
            service_account_path = gcp_cfg.gcp.get("service_account_path")

            if auth_by == "json" and service_account_path:
                if not os.path.isabs(service_account_path):
                    from lib.cuckoo.common.constants import CUCKOO_ROOT
                    service_account_path = os.path.join(CUCKOO_ROOT, service_account_path)
                if os.path.exists(service_account_path):
                    self.subscriber = pubsub_v1.SubscriberClient.from_service_account_json(service_account_path)
                    self.storage_client = storage.Client.from_service_account_json(service_account_path)
                else:
                    log.error("GCP service account file not found: %s", service_account_path)
                    sys.exit(1)
            else:
                self.subscriber = pubsub_v1.SubscriberClient()
                self.storage_client = storage.Client(project=self.project_id)

            self.subscription_path = self.subscriber.subscription_path(self.project_id, self.subscription_id)
        except ImportError:
            log.error("GCP Pub/Sub dependencies not installed. Please run `poetry install --extras gcp` or `pip install google-cloud-pubsub google-cloud-storage`")
            sys.exit(1)
        except Exception as e:
            log.error("Failed to initialize GCP Pub/Sub client: %s", e)
            sys.exit(1)

        init_database()
        self.db = Database()

        self._init_clients()

        self.cuckoo_cfg = Config()
        self.tmp_path = os.path.join(self.cuckoo_cfg.cuckoo.get("tmppath", "/tmp"), "cape-external")
        if not path_exists(self.tmp_path):
            try:
                os.makedirs(self.tmp_path)
            except Exception as e:
                log.error("Failed to create temporary directory %s: %s", self.tmp_path, e)
                sys.exit(1)

    def _init_clients(self):
        """(Re)initialize Google Cloud clients."""
        from lib.cuckoo.common.gcp import gcp_cfg
        from google.cloud import pubsub_v1
        from google.cloud import storage

        auth_by = gcp_cfg.gcp.get("auth_by", "vm")
        service_account_path = gcp_cfg.gcp.get("service_account_path")

        if auth_by == "json" and service_account_path:
            if not os.path.isabs(service_account_path):
                from lib.cuckoo.common.constants import CUCKOO_ROOT
                service_account_path = os.path.join(CUCKOO_ROOT, service_account_path)
            if os.path.exists(service_account_path):
                self.subscriber = pubsub_v1.SubscriberClient.from_service_account_json(service_account_path)
                self.storage_client = storage.Client.from_service_account_json(service_account_path)
            else:
                log.error("GCP service account file not found: %s", service_account_path)
                # Fallback to default credentials
                self.subscriber = pubsub_v1.SubscriberClient()
                self.storage_client = storage.Client(project=self.project_id)
        else:
            self.subscriber = pubsub_v1.SubscriberClient()
            self.storage_client = storage.Client(project=self.project_id)

        self.subscription_path = self.subscriber.subscription_path(self.project_id, self.subscription_id)

    def process_message(self, message: Any):
        msg_id = message.message_id
        with self.ids_lock:
            if msg_id in self.processing_ids:
                log.warning("[%s] Already processing this message, ignoring redelivery", msg_id)
                return
            self.processing_ids.add(msg_id)

        correlation_id = msg_id
        import time
        start_time = time.time()
        try:
            payload = json.loads(message.data.decode("utf-8"))
            correlation_id = payload.get("uuid") or payload.get("transaction_id") or msg_id

            # Create a localized logger with correlation_id
            mlog = GCPServiceLogger(log, {"correlation_id": correlation_id})

            sample_hash = payload.get("sample_hash")
            gcs_uri = payload.get("gcs_uri")

            if not sample_hash and gcs_uri:
                # Extract hash from URI if missing
                sample_hash = os.path.basename(gcs_uri)

            if not sample_hash or not gcs_uri:
                # If we only have hash, construct URI using samples_bucket
                if sample_hash and self.samples_bucket:
                    gcs_uri = f"gs://{self.samples_bucket}/{sample_hash}"
                else:
                    mlog.error("Missing sample_hash or gcs_uri in payload")
                    message.nack()
                    return
            sandbox_options = payload.get("sandbox_options", "")
            parent_id = payload.get("parent_id", "")
            transaction_id = payload.get("transaction_id", "")
            sample_name = payload.get("name", "sample")
            source = payload.get("source", "")

            mlog.info("Received message for sample: %s (name: %s, source: %s)", sample_hash, sample_name, source)

            category = None
            if "category=static" in sandbox_options:
                category = "static"

            sandbox_options = sandbox_options or ""
            if sandbox_options:
                sandbox_options += f",name={sample_name}"
            else:
                sandbox_options += f"name={sample_name}"

            # Format custom fields with truncation to fit 255 chars
            custom_parts = []
            if parent_id:
                custom_parts.append(f"parent_id:{parent_id}")
            if transaction_id:
                custom_parts.append(f"transaction_id:{transaction_id}")
            if source:
                custom_parts.append(f"source:{source}")
            if sample_name:
                custom_parts.append(f"name:{sample_name}")

            custom = ",".join(custom_parts)
            if len(custom) > 255:
                custom = custom[:252] + "..."

            # Check if sample exists locally
            sample_hash = os.path.basename(sample_hash)
            local_path = os.path.join(CUCKOO_ROOT, "storage", "binaries", sample_hash)

            if not path_exists(local_path):
                mlog.info("Sample %s not found locally, fetching from GCS: %s", sample_hash, gcs_uri)
                fd, temp_path = tempfile.mkstemp(prefix=sample_name, dir=self.tmp_path)
                os.close(fd)
                dl_start = time.time()

                # Retry download once with fresh client if TransportError/SSL issues occur
                success = False
                for attempt in range(2):
                    try:
                        if download_from_gcs(gcs_uri, temp_path, logger=mlog, client=self.storage_client):
                            success = True
                            break
                    except Exception as e:
                        if attempt == 0:
                            mlog.warning("Transient error during download, recreating client and retrying: %s", e)
                            self._init_clients()
                        else:
                            mlog.error("Persistent error during download: %s", e)

                if success:
                    mlog.info("Download finished in %.2f seconds", time.time() - dl_start)
                    local_path = temp_path
                else:
                    mlog.error("Failed to download sample from GCS: %s", gcs_uri)
                    message.nack()
                    return

            # Submit to CAPE
            try:
                submit_start = time.time()
                task_ids, extra_details = submit_file(
                    db=self.db,
                    file_path=local_path,
                    options=sandbox_options,
                    custom=custom,
                    category=category,
                    filename=sample_name,
                )
                if task_ids:
                    mlog.info("Successfully submitted task(s) %s for sample %s in %.2f seconds", task_ids, sample_hash, time.time() - submit_start)
                    message.ack()
                elif extra_details.get("errors"):
                    # Check if it was a duplicate, empty file, or junk
                    error_str = str(extra_details["errors"])
                    if "Duplicate" in error_str or "junk_filter" in error_str or "Empty file" in error_str:
                        mlog.info("Sample %s skipped: %s", sample_hash, error_str)
                        message.ack()
                    else:
                        mlog.error("Failed to add task to database for sample %s: %s", sample_hash, extra_details["errors"])
                        message.nack()
                else:
                    # No tasks but no errors means it was filtered (junk)
                    mlog.info("Sample %s processed but no tasks created (filtered).", sample_hash)
                    message.ack()
            except Exception as e:
                import traceback
                mlog.error("Failed to add task to database: %s\n%s", e, traceback.format_exc())
                message.nack()
            finally:
                # We do NOT delete local_path or cuckoo-sflock here.
                # CAPE's AnalysisManager will copy them to storage/binaries when analysis starts.
                # Background cleaner handles /tmp disk space.

                self.db.session.remove()
                # Force GC to close any dangling FDs from sflock or File objects
                import gc
                gc.collect()

        except Exception as e:
            log.error("[%s] Error processing message: %s", correlation_id, e)
            message.nack()
            self.db.session.remove()
        finally:
            with self.ids_lock:
                self.processing_ids.discard(msg_id)
            log.info("[%s] Total processing time: %.2f seconds", correlation_id, time.time() - start_time)

    def start(self):
        log.info("Starting GCP Pub/Sub subscriber on %s", self.subscription_path)

        from lib.cuckoo.common.gcp import gcp_cfg
        max_messages = 5
        lease_duration = 1800
        if hasattr(gcp_cfg, "samples_pubsub"):
            max_messages = int(gcp_cfg.samples_pubsub.get("max_messages", 5))
            lease_duration = int(gcp_cfg.samples_pubsub.get("lease_duration", 1800))

        # Increase lease duration for big files and limit concurrency
        # Support both old and new parameter names for max compatibility
        kwargs = {
            "max_messages": max_messages,
            "max_duration_per_lease_extension": lease_duration,
        }
        # Some versions use max_lease_duration
        if hasattr(self.pubsub_v1.types.FlowControl, "max_lease_duration"):
            kwargs["max_lease_duration"] = lease_duration

        flow_control = self.pubsub_v1.types.FlowControl(**kwargs)

        while True:
            streaming_pull_future = self.subscriber.subscribe(
                self.subscription_path,
                callback=self.process_message,
                flow_control=flow_control
            )

            try:
                # result() keeps the main thread alive while the subscriber runs in background
                streaming_pull_future.result()
            except Exception as e:
                log.error("Subscriber exited with error: %s. Restarting in 10 seconds...", e)
                try:
                    streaming_pull_future.cancel()
                except Exception:
                    pass
                import time
                time.sleep(10)
            except KeyboardInterrupt:
                try:
                    streaming_pull_future.cancel()
                except Exception:
                    pass
                break

def main():
    service = GCPPubSubService()
    service.start()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log.info("Shutting down...")
        sys.exit(0)
    except Exception as e:
        log.error("Fatal error in main: %s", e)
        sys.exit(1)
