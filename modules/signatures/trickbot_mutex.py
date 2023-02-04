from lib.cuckoo.common.abstracts import Signature


class TrickBotMutexes(Signature):
    name = "trickbot_mutex"
    description = "Attempts to create a known TrickBot mutex."
    weight = 3
    severity = 3
    categories = ["banker", "trojan"]
    families = ["TrickBot"]
    authors = ["Eoin Miller", "Mark Parsons"]
    minimum = "0.5"
    mbcs = ["OC0003", "C0042"]  # micro-behaviour

    def run(self):
        if self.check_mutex("Global\\TrickBot") or self.check_mutex("Global\\MGlob"):
            return True

        return False
