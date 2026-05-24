#!/usr/bin/env python
# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import json
import logging
import os
import sys
import tempfile
import warnings

# Mute Google Cloud's Python version support warning for Python 3.10
warnings.filterwarnings("ignore", category=FutureWarning, module="google.api_core")

sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.gcp import download_from_gcs
from lib.cuckoo.common.path_utils import path_exists
from lib.cuckoo.core.database import Database, init_database
from lib.cuckoo.core.startup import check_user_permissions
from utils.submit import submit_file

check_user_permissions(os.getenv("CAPE_AS_ROOT", False))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
log = logging.getLogger("gcp_pubsub_service")

class GCPServiceLogger(logging.LoggerAdapter):
    def process(self, msg, kwargs):
        correlation_id = self.extra.get("correlation_id")
        if correlation_id:
            msg = f"[{correlation_id}] {msg}"
        return msg, kwargs

class GCPPubSubService:
    def __init__(self):
        self.gcp_cfg = Config("gcp")
        self.project_id = self.gcp_cfg.gcp.get("project")
        self.subscription_id = os.getenv("GCP_SUBSCRIPTION_ID") or self.gcp_cfg.gcp.get("subscription_id")

        if not self.project_id or "<project_id>" in self.project_id:
            log.error("GCP project ID not set. Please update gcp.conf or set GCP_PROJECT_ID env var")
            sys.exit(1)

        # Ensure project ID is available for all GCP client libraries
        if not os.environ.get("GOOGLE_CLOUD_PROJECT"):
            os.environ["GOOGLE_CLOUD_PROJECT"] = self.project_id
        if not os.environ.get("GCLOUD_PROJECT"):
            os.environ["GCLOUD_PROJECT"] = self.project_id
        if not self.subscription_id or "<subscription_id>" in self.subscription_id:
            log.error("GCP subscription ID not set. Please update gcp.conf or set GCP_SUBSCRIPTION_ID env var")
            sys.exit(1)

        try:
            from google.cloud import pubsub_v1
            self.pubsub_v1 = pubsub_v1
        except ImportError:
            log.error("google-cloud-pubsub not installed. Run `pip install google-cloud-pubsub`")
            sys.exit(1)

        service_account_path = self.gcp_cfg.gcp.get("service_account_path")
        if service_account_path and os.path.exists(service_account_path):
            self.subscriber = self.pubsub_v1.SubscriberClient.from_service_account_json(service_account_path)
        else:
            self.subscriber = self.pubsub_v1.SubscriberClient()

        self.subscription_path = self.subscriber.subscription_path(self.project_id, self.subscription_id)

        # Initialize storage client for reuse to avoid SSLEOFError and repeated auth
        try:
            from google.cloud import storage
            if service_account_path and os.path.exists(service_account_path):
                self.storage_client = storage.Client.from_service_account_json(service_account_path)
            else:
                self.storage_client = storage.Client(project=self.project_id)
        except ImportError:
            log.error("google-cloud-storage not installed. Run `pip install google-cloud-storage`")
            sys.exit(1)
        except Exception as e:
            log.error("Failed to initialize GCP storage client: %s", e)
            sys.exit(1)

        init_database()
        self.db = Database()

        self.cuckoo_cfg = Config()
        self.tmp_path = os.path.join(self.cuckoo_cfg.cuckoo.get("tmppath", "/tmp"), "cape-external")
        if not path_exists(self.tmp_path):
            try:
                os.makedirs(self.tmp_path)
            except Exception as e:
                log.error("Failed to create temporary directory %s: %s", self.tmp_path, e)
                sys.exit(1)

    def process_message(self, message):
        correlation_id = message.message_id
        try:
            payload = json.loads(message.data.decode("utf-8"))
            correlation_id = payload.get("uuid") or payload.get("transaction_id") or message.message_id

            # Create a localized logger with correlation_id
            mlog = GCPServiceLogger(log, {"correlation_id": correlation_id})

            sample_hash = payload.get("sample_hash")
            gcs_uri = payload.get("gcs_uri")
            if not sample_hash or not gcs_uri:
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
            is_temp = False

            if not path_exists(local_path):
                mlog.info("Sample %s not found locally, fetching from GCS: %s", sample_hash, gcs_uri)
                fd, temp_path = tempfile.mkstemp(prefix=sample_name, dir=self.tmp_path)
                os.close(fd)
                if download_from_gcs(gcs_uri, temp_path, logger=mlog, client=self.storage_client):
                    local_path = temp_path
                    is_temp = True
                else:
                    mlog.error("Failed to download sample from GCS: %s", gcs_uri)
                    message.nack()
                    return

            # Submit to CAPE
            try:
                task_ids = submit_file(
                    db=self.db,
                    file_path=local_path,
                    options=sandbox_options,
                    custom=custom,
                    category=category,
                    filename=sample_name,
                )
                if task_ids:
                    mlog.info("Successfully submitted task(s) %s for sample %s", task_ids, sample_hash)
                    message.ack()
                else:
                    mlog.error("Failed to add task to database for sample %s", sample_hash)
                    message.nack()
            except Exception as e:
                mlog.error("Failed to add task to database: %s", e)
                message.nack()
            finally:
                if is_temp and path_exists(local_path):
                    try:
                        os.unlink(local_path)
                    except Exception as e:
                        mlog.warning("Failed to delete temp file %s: %s", local_path, e)
                self.db.session.remove()

        except Exception as e:
            log.error("[%s] Error processing message: %s", correlation_id, e)
            message.nack()
            self.db.session.remove()

    def start(self):
        log.info("Starting GCP Pub/Sub subscriber on %s", self.subscription_path)

        while True:
            streaming_pull_future = self.subscriber.subscribe(self.subscription_path, callback=self.process_message)

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
