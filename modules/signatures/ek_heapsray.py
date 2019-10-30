from lib.cuckoo.common.abstracts import Signature

class HeapSpray_JS(Signature):
    name = "heapspray_js"
    description = "Executes obfuscated JavaScript which contains common heap spray memory locations indicative of an exploit attempt"
    weight = 3
    severity = 3
    categories = ["exploit"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)

    filter_categories = set(["browser"])
    # backward compat
    filter_apinames = set(["JsEval", "COleScript_Compile", "COleScript_ParseScriptText"])

    def on_call(self, call, process):
        indicators = [
                "0x0a0a0a0a",
                "0x0b0b0b0b",
                "0x0c0c0c0c",
                "0x0d0d0d0d",
                "0x0e0e0e0e",
                "0x04040404",
                "0x05050505",
                "0x07070707",
                "0x08080808",
                "0x09090909",
                "0x0a040a04",
                "0x14141414",
                "0x41414141",
                "%u0a%u0a%u0a%u0a",
                "%u0b%u0b%u0b%u0b",
                "%u0c%u0c%u0c%u0c",
                "%u0d%u0d%u0d%u0d",
                "%u0e%u0e%u0e%u0e",
                "%u04%u04%u04%u04",
                "%u05%u05%u05%u05",
                "%u07%u07%u07%u07",
                "%u08%u08%u08%u08",
                "%u09%u09%u09%u09",
                "%u0a%u04%u0a%u04",
                "%u14%u14%u14%u14",
                "%u41%u41%u41%u41",
                "%u0a0a%u0a0a",
                "%u0b0b%u0b0b",
                "%u0c0c%u0c0c",
                "%u0d0d%u0d0d",
                "%u0e0e%u0e0e",
                "%u0404%u0404",
                "%u0505%u0505",
                "%u0707%u0707",
                "%u0808%u0808",
                "%u0909%u0909",
                "%u0a04%u0a04",
                "%u1414%u1414",
                "%u4141%u4141",
            ]

        if call["api"] == "JsEval":
            buf = self.get_argument(call, "Javascript")
        else:
            buf = self.get_argument(call, "Script")

        for indicator in indicators:
            if indicator in buf.lower():
                return True
