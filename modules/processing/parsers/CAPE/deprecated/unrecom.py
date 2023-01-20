import string
import xml.etree.ElementTree as ET
from io import StringIO
from zipfile import ZipFile

from Cryptodome.Cipher import ARC4


def extract_embedded(zip_data):
    raw_embedded = None
    archive = StringIO(zip_data)
    with ZipFile(archive) as zip:
        for name in zip.namelist():  # get all the file names
            if name == "load/ID":  # contains first part of key
                partial_key = zip.read(name)
                enckey = f"{partial_key}DESW7OWKEJRU4P2K"  # complete key
            if name == "load/MANIFEST.MF":  # this is the embedded jar
                raw_embedded = zip.read(name)
    if raw_embedded is None:
        return None
    # Decrypt the raw file
    return ARC4.new(enckey).decrypt(raw_embedded)


def parse_embedded(data):
    newzipdata = data
    # Write new zip file to memory instead of to disk
    with StringIO(newzipdata) as newZip:
        with ZipFile(newZip) as zip:
            for name in zip.namelist():
                if name == "config.xml":  # this is the config in clear
                    config = zip.read(name)
    return config


def parse_config(config):
    xml = [x for x in config if x in string.printable]
    root = ET.fromstring(xml)
    raw_config = {}
    for child in root:
        if child.text.startswith("Unrecom"):
            raw_config["Version"] = child.text
        else:
            raw_config[child.attrib["key"]] = child.text
    return {
        "Version": raw_config["Version"],
        "Delay": raw_config["delay"],
        "Domain": raw_config["dns"],
        "Extension": raw_config["extensionname"],
        "Install": raw_config["install"],
        "Port1": raw_config["p1"],
        "Port2": raw_config["p2"],
        "Password": raw_config["password"],
        "PluginFolder": raw_config["pluginfoldername"],
        "Prefix": raw_config["prefix"],
    }


def extract_config(data):
    embedded = extract_embedded(data)
    if embedded is None:
        return None
    config = parse_embedded(embedded)
    return parse_config(config) if config is not None else None
