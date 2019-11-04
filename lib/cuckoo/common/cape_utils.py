from __future__ import absolute_import
import os
import sys
import logging
import tempfile
import hashlib
import subprocess
from io import BytesIO
from collections import Mapping, Iterable

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.objects import CAPE_YARA_RULEPATH, File
import six
from six.moves import map

try:
    from malwareconfig import fileparser
    from malwareconfig.modules import __decoders__, __preprocessors__
    HAVE_malwareconfig = True
except ImportError:
    HAVE_malwareconfig = False

log = logging.getLogger(__name__)

pe_map = {
    "PE32+": ": 64-bit ",
    "PE32": ": 32-bit ",
}


cfg = Config()
BUFSIZE = int(cfg.processing.analysis_size_limit)

def hash_file(method, path):
    """Calculates an hash on a file by path.
    @param method: callable hashing method
    @param path: file path
    @return: computed hash string
    """
    f = open(path, "rb")
    h = method()
    while True:
        buf = f.read(BUFSIZE)
        if not buf:
            break
        h.update(buf)
    return h.hexdigest()

def upx_harness(raw_data):
    upxfile = tempfile.NamedTemporaryFile(delete=False)
    upxfile.write(raw_data)
    upxfile.close()
    try:
        ret = subprocess.call("(upx -d %s)" % upxfile.name, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except Exception as e:
        log.error("CAPE: UPX Error %s", e)
        os.unlink(upxfile.name)
        return

    if ret == 0:
        sha256 = hash_file(hashlib.sha256, upxfile.name)
        newname = os.path.join(os.path.dirname(upxfile.name), sha256)
        os.rename(upxfile.name, newname)
        log.info("CAPE: UPX - Statically unpacked binary %s.", upxfile.name)
        return newname
    elif ret == 127:
        log.error("CAPE: Error - UPX not installed.")
    elif ret == 2:
        log.error("CAPE: Error - UPX 'not packed' exception.")
    else:
        log.error("CAPE: Unknown error - check UPX is installed and working.")

    os.unlink(upxfile.name)
    return

def convert(data):
    if isinstance(data, six.text_type):
        return str(data)
    if isinstance(data, str):
        return str(data)
    elif isinstance(data, Mapping):
        return dict(list(map(convert, six.iteritems(data))))
    elif isinstance(data, Iterable):
        return type(data)(list(map(convert, data)))
    else:
        return data

parser_path = os.path.join(CUCKOO_ROOT, "modules", "processing", "parsers")
if parser_path not in sys.path:
    sys.path.append(parser_path)

try:
    from malwareconfig import JavaDropper
    from plugxconfig import plugx
    from mwcp import reporter
except ImportError as e:
    print(e)

suppress_parsing_list = ["Cerber", "Emotet_Payload", "Ursnif", "QakBot"]

def static_config_parsers(yara_hit, file_data, cape_config):
    # Process CAPE Yara hits

        cape_name = yara_hit.replace('_', ' ')

        # Attempt to import a parser for the hit
        # DC3-MWCP
        mwcp_loaded = False
        if cape_name:
            try:
                mwcp_parsers = os.path.join(CUCKOO_ROOT, "modules", "processing", "parsers", "mwcp", "parsers")
                mwcp = reporter.Reporter(parserdir=mwcp_parsers)
                kwargs = {}
                mwcp.run_parser(cape_name, data=file_data, **kwargs)
                if mwcp.errors == []:
                    log.info("CAPE: Imported DC3-MWCP parser %s", cape_name)
                    mwcp_loaded = True
                else:
                    error_lines = mwcp.errors[0].split("\n")
                    for line in error_lines:
                        if line.startswith('ImportError: '):
                            log.info("CAPE: DC3-MWCP parser: %s", line.split(': ')[1])
            except (ImportError, IndexError) as e:
                log.error(e)

            # malwareconfig
            malwareconfig_loaded = False
            if mwcp_loaded is False:
                try:
                    if cape_name in __decoders__:
                        module = __decoders__[cape_name]['obj']()
                        log.info("CAPE: Imported malwareconfig.com parser %s", cape_name)
                except (ImportError, IndexError):
                    log.info("CAPE: malwareconfig.com parser: No module named %s", cape_name)

            # Get config data
            if mwcp_loaded:
                try:
                    if "cape_config" not in cape_config:
                        cape_config["cape_config"] = {}
                        cape_config["cape_config"] = convert(mwcp.metadata)
                    else:
                        new = convert(mwcp.metadata)
                        for key in new.keys():
                            cape_config["cape_config"][key] = list(set(cape_config["cape_config"][key] + new[key]))
                except Exception as e:
                    log.error("CAPE: DC3-MWCP config parsing error with %s: %s", cape_name, e)
            elif malwareconfig_loaded:
                try:
                    if not "cape_config" in cape_config:
                        cape_config["cape_config"] = {}
                    file_info = fileparser.FileParser(file_path=BytesIO(file_data))
                    module.set_file(file_info)
                    module.get_config()
                    malwareconfig_config = module.config
                    if isinstance(malwareconfig_config, list):
                        for (key, value) in six.iteritems(malwareconfig_config[0]):
                            cape_config["cape_config"].update({key: [value]})
                    elif isinstance(malwareconfig_config, dict):
                        for (key, value) in six.iteritems(malwareconfig_config):
                            cape_config["cape_config"].update({key: [value]})
                except Exception as e:
                    log.error("CAPE: malwareconfig parsing error with %s: %s", cape_name, e)
            if "cape_config" in cape_config:
                if cape_config["cape_config"] == {}:
                    del cape_config["cape_config"]

        return cape_config

def static_extraction(path):
    cape_config = dict()
    try:
        hits = File(path).get_yara(CAPE_YARA_RULEPATH)
        if not hits:
            return False
        # ToDo not public
        if any([hit["name"].endswith("_TCR") for hit in hits]):
            return True
        # Get the file data
        with open(path, "r") as file_open:
            file_data = file_open.read()
        for hit in hits:
            config = static_config_parsers(hit["name"], file_data, cape_config)
            if config:
                return config
        return False
    except Exception as e:
        log.error(e)

    return False
