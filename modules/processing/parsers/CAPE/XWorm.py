from lib.parsers_aux.ratking import RATConfigParser


def extract_config(data: bytes):
    return RATConfigParser(data).report.get("config", {})
