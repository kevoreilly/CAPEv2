import logging

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.core.database import Database

log = logging.getLogger(__name__)
main_db = Database()


class RunStatistics(Report):
    "Notify us about analysis is done"

    order = 10001

    def getDroppedFileCount(self, results):
        """Count DroppedFiles.
        @return int value.
        """
        return len(results.get("dropped"))

    def getRuningProcessesCount(self, results):
        """Count running processes.
        @return int value.
        """
        if results.get("behavior").get("processtree"):
            return len(results.get("behavior").get("processtree"))

    def getApiCallsAndRegistryCount(self, results):
        """Count api calss and registry modified.
        return two int values.
        """
        calls_count = 0
        registry_keys_count = 0
        try:
            processes = results.get("behavior").get("processes")
            for process in processes:
                calls_count += len(process.get("calls"))
                for call in process.get("calls"):
                    if call.get("api") in ("RegSetValueEx", "RegCreateKey", "RegDeleteKey"):
                        registry_keys_count += 1
            return calls_count, registry_keys_count
        except Exception as e:
            log.error('Failed to RunStatistics "%s" :%s', self.__class__.__name__, e)

    def getDomainsCount(self, results):
        """Count Domains
        @return int value.
        """
        return len(results.get("network", {}).get("domains", []))

    def getSignaturesAndAlertCount(self, results):
        """Count signature, signature alert, crash issues, anti issues.
        @return four int values.
        """
        try:
            signature_count = len(results.get("signatures"))
            signature_alert_count = 0
            crash_issues = 0
            anti_issues = 0
            signatures = results.get("signatures")
            for signature in signatures:
                if signature.get("alert"):
                    signature_alert_count += 1
                if "crash" in signature.get("name"):
                    crash_issues += 1
                if "anti" in signature.get("name"):
                    anti_issues += 1
            return signature_count, signature_alert_count, crash_issues, anti_issues
        except Exception as e:
            log.error('Failed to RunStatistics "%s" :%s', self.__class__.__name__, e)

    def getFilesWrittenCount(self, results):
        """Count fileswirtten.
        @return int value.
        """
        return len(results.get("behavior").get("summary").get("write_files"))

    def run(self, results):
        task_id = int(results.get("info", {}).get("id"))

        detail = {
            "dropped_files": 0,
            "running_processes": 0,
            "api_calls": 0,
            "domains": 0,
            "signatures_total": 0,
            "signatures_alert": 0,
            "files_written": 0,
            "registry_keys_modified": 0,
            "crash_issues": 0,
            "anti_issues": 0,
        }
        detail["dropped_files"] = self.getDroppedFileCount(results)
        detail["running_processes"] = self.getRuningProcessesCount(results)
        detail["api_calls"], detail["registry_keys_modified"] = self.getApiCallsAndRegistryCount(results)
        detail["domains"] = self.getDomainsCount(results)
        (
            detail["signatures_total"],
            detail["signatures_alert"],
            detail["crash_issues"],
            detail["anti_issues"],
        ) = self.getSignaturesAndAlertCount(results)
        detail["files_written"] = self.getFilesWrittenCount(results)
        if main_db.add_statistics_to_task(task_id, detail):
            log.debug("Run statistics sucessed!")
        else:
            log.debug("Run statistics failed!")
