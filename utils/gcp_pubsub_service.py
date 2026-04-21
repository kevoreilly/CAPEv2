#!/usr/bin/env python
# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import json
import logging
import os
import sys
import tempfile
import threading

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

class GCPPubSubService:
    def __init__(self):
        self.gcp_cfg = Config("gcp")
        self.project_id = self.gcp_cfg.gcp.get("project")
        self.subscription_id = os.getenv("GCP_SUBSCRIPTION_ID") or self.gcp_cfg.gcp.get("subscription_id")

        if not self.project_id or "<project_id>" in self.project_id:
            log.error("GCP project ID not set. Please update gcp.conf or set GCP_PROJECT_ID env var")
            sys.exit(1)
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

        init_database()
        self.db = Database()

    def process_message(self, message):
        try:
            payload = json.loads(message.data.decode("utf-8"))
            log.info("Received payload: %s", payload.get("uuid"))

            sample_hash = payload.get("sample_hash")
            gcs_uri = payload.get("gcs_uri")
            sandbox_options = payload.get("sandbox_options", "")
            parent_id = payload.get("parent_id", "")
            transaction_id = payload.get("transaction_id", "")
            sample_name = payload.get("name", "sample")
            source = payload.get("source", "")
            category = None
            if "category=static" in sandbox_options:
                category = "static"

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
                log.info("Sample %s not found locally, fetching from GCS: %s", sample_hash, gcs_uri)
                fd, temp_path = tempfile.mkstemp()
                os.close(fd)
                if download_from_gcs(gcs_uri, temp_path):
                    local_path = temp_path
                    is_temp = True
                else:
                    log.error("Failed to download sample from GCS")
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
                )
                if task_ids:
                    log.info("Successfully submitted task(s): %s", task_ids)
                    message.ack()
                else:
                    log.error("Failed to add task to database")
                    message.nack()
            except Exception as e:
                log.error("Failed to add task to database: %s", e)
                message.nack()
            finally:
                if is_temp and path_exists(local_path):
                    try:
                        os.unlink(local_path)
                    except Exception as e:
                        log.warning("Failed to delete temp file %s for task, %s: %s", local_path, payload.get("uuid"), e)

        except Exception as e:
            log.error("Error processing message: %s", e)
            message.nack()

    def start(self):
        log.info("Starting GCP Pub/Sub subscriber on %s", self.subscription_path)
        streaming_pull_future = self.subscriber.subscribe(self.subscription_path, callback=self.process_message)

        # Use a threading event to handle graceful shutdown
        self.shutdown_event = threading.Event()

        try:
            # result() keeps the main thread alive while the subscriber runs in background
            streaming_pull_future.result()
        except Exception as e:
            log.error("Subscriber exited with error: %s", e)
            streaming_pull_future.cancel()

def main():
    service = GCPPubSubService()
    service.start()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log.info("Shutting down...")
        sys.exit(0)
