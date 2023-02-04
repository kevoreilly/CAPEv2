from lib.cuckoo.common.abstracts import Signature


class TrickBotTaskDelete(Signature):
    name = "trickbot_task_delete"
    description = "Exhibits behavior characteristic of TrickBot banker trojan"
    severity = 3
    weight = 3
    categories = ["banker", "trojan"]
    families = ["TrickBot"]
    authors = ["Eoin Miller", "Mark Parsons"]
    minimum = "1.0"
    evented = True
    ttps = ["T1107"]  # MITRE v6
    ttps += ["T1070"]  # MITRE v6,7,8
    ttps += ["T1070.004"]  # MITRE v7,8
    mbcs = ["OB0006", "F0007"]
    mbcs += ["OC00001", "C0047"]  # micro-behaviour

    filter_apinames = set(["DeleteFileW"])

    def on_call(self, call, process):
        if call["api"] == ("DeleteFileW") and (
            self.get_argument(call, "FileName").endswith("TrickBot.job")
            or self.get_argument(call, "FileName").endswith("TrickBot")
            or self.get_argument(call, "FileName").endswith("Drivers update.job")
            or self.get_argument(call, "FileName").endswith("Tasks\\Bot.job")
        ):
            self.data.append({"file": self.get_argument(call, "FileName")})
            if self.pid:
                self.mark_call()
            return True

        return None
