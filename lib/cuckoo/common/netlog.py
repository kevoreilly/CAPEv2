# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import logging
import struct
import datetime

try:
    import bson

    HAVE_BSON = True
except ImportError:
    HAVE_BSON = False
else:
    # The BSON module provided by pymongo works through its "BSON" class.
    if hasattr(bson, "BSON"):
        bson_decode = lambda d: bson.BSON(d).decode()
    # The BSON module provided by "pip3 install bson" works through the
    # "loads" function (just like pickle etc.)
    elif hasattr(bson, "loads"):
        bson_decode = lambda d: bson.loads(d)
    else:
        HAVE_BSON = False

from lib.cuckoo.common.defines import REG_SZ, REG_EXPAND_SZ
from lib.cuckoo.common.defines import REG_DWORD_BIG_ENDIAN
from lib.cuckoo.common.defines import REG_DWORD_LITTLE_ENDIAN
from lib.cuckoo.common.exceptions import CuckooResultError
from lib.cuckoo.common.logtbl import table as LOGTBL
from lib.cuckoo.common.utils import get_filename_from_path, default_converter

log = logging.getLogger(__name__)

###############################################################################
# Generic BSON based protocol - by rep
# Allows all kinds of languages / sources to generate input for Cuckoo,
# thus we can reuse report generation / signatures for other API trace sources.
###############################################################################

TYPECONVERTERS = {"h": lambda v: "0x%08x" % default_converter(v), "p": lambda v: "0x%.08x" % default_converter(v)}

# 20 Mb max message length.
MAX_MESSAGE_LENGTH = 20 * 1024 * 1024


def pointer_converter_32bit(v):
    return "0x%08x" % (v % 2 ** 32)


def pointer_converter_64bit(v):
    return "0x%016x" % (v % 2 ** 64)


def default_converter_32bit(v):
    if isinstance(v, int) and v < 0:
        return v % 2 ** 32

    # Try to avoid various unicode issues through usage of latin-1 encoding.
    if isinstance(v, str):
        return v.decode("latin-1")
    return v


def default_converter_64bit(v):
    # Don't convert signed 64-bit integers into unsigned 64-bit integers as
    # MongoDB doesn't support 64-bit unsigned integers (and ElasticSearch
    # probably doesn't either).
    # if isinstance(v, (int, long)) and v < 0:
    # return v % 2**64

    # Try to avoid various unicode issues through usage of latin-1 encoding.
    if isinstance(v, str):
        return v.decode("latin-1")
    return v


def check_names_for_typeinfo(arginfo):
    argnames = [i[0] if type(i) in (list, tuple) else i for i in arginfo]

    converters = []
    for i in arginfo:
        if type(i) in (list, tuple):
            r = TYPECONVERTERS.get(i[1], None)
            if not r:
                log.debug("Analyzer sent unknown format " "specifier '{0}'".format(i[1]))
                r = default_converter
            converters.append(r)
        else:
            converters.append(default_converter)

    return argnames, converters


class BsonParser(object):
    """Interprets .bson logs from the monitor.
    The monitor provides us with "info" messages that explain how the function
    arguments will come through later on. This class remembers these info
    mappings and then transforms the api call messages accordingly.
    Other message types typically get passed through after renaming the
    keys slightly.
    """

    converters_32bit = {
        None: default_converter_32bit,
        "p": pointer_converter_32bit,
        "x": pointer_converter_32bit,
    }

    converters_64bit = {
        None: default_converter_64bit,
        "p": pointer_converter_64bit,
        "x": pointer_converter_32bit,
    }

    def __init__(self, fd, task_id=None):
        self.fd = fd
        self.infomap = {}

        self.flags_value = {}
        self.flags_bitmask = {}
        self.pid = None
        self.is_64bit = False
        self.buffer_sha1 = None
        self.task_id = task_id

        if not HAVE_BSON:
            log.critical("Starting BsonParser, but bson is not available! (install with `pip3 install bson`)")

    def close(self):
        pass

    def resolve_flags(self, apiname, argdict, flags):
        # Resolve 1:1 values.
        for argument, values in self.flags_value[apiname].items():
            if isinstance(argdict[argument], str):
                value = int(argdict[argument], 16)
            else:
                value = argdict[argument]

            if value in values:
                flags[argument] = values[value]

        # Resolve bitmasks.
        for argument, values in self.flags_bitmask[apiname].items():
            if argument in flags:
                continue

            flags[argument] = []

            if isinstance(argdict[argument], str):
                value = int(argdict[argument], 16)
            else:
                value = argdict[argument]

            for key, flag in values:
                # TODO Have the monitor provide actual bitmasks as well.
                if (value & key) == key:
                    flags[argument].append(flag)

            flags[argument] = "|".join(flags[argument])

    def determine_unserializers(self, arginfo):
        """Determine which unserializers (or converters) have to be used in
        order to parse the various arguments for this function call. Maintains
        whether the current bson is 32-bit or 64-bit."""
        argnames, converters = [], []

        for argument in arginfo:
            if isinstance(argument, (tuple, list)):
                argument, argtype = argument
            else:
                argtype = None

            if self.is_64bit:
                converter = self.converters_64bit[argtype]
            else:
                converter = self.converters_32bit[argtype]

            argnames.append(argument)
            converters.append(converter)

        return argnames, converters

    def read_next_message(self):
        # self.fd.seek(0)
        while True:
            data = self.fd.read(4)
            if not data:
                return

            if len(data) != 4:
                log.critical("BsonParser lacking data.")
                return

            blen = struct.unpack("I", data)[0]
            if blen > MAX_MESSAGE_LENGTH:
                log.critical("BSON message larger than MAX_MESSAGE_LENGTH, " "stopping handler.")
                return False

            data += self.fd.read(blen - 4)

            if len(data) < blen:
                log.critical("BsonParser lacking data.")
                return

            try:
                dec = bson_decode(data)
            except Exception as e:
                log.warning("BsonParser decoding problem {0} on " "data[:50] {1}".format(e, repr(data[:50])))
                return False

            mtype = dec.get("type", "none")
            index = dec.get("I", -1)
            tid = dec.get("T", 0)
            time = dec.get("t", 0)
            caller = dec.get("R", 0)
            parentcaller = dec.get("P", 0)
            repeated = dec.get("r", 0)

            context = [index, repeated, 1, 0, tid, time, caller, parentcaller]

            if mtype == "info":
                # API call index info message, explaining the argument names, etc.
                name = dec.get("name", "NONAME")
                arginfo = dec.get("args", [])
                category = dec.get("category")

                # Bson dumps that were generated before cuckoomon exported the
                # "category" field have to get the category using the old method.
                if not category:
                    # Try to find the entry/entries with this api name.
                    category = [_ for _ in LOGTBL if _[0] == name]

                    # If we found an entry, take its category, otherwise we take
                    # the default string "unknown."
                    category = category[0][1] if category else "unknown"

                argnames, converters = check_names_for_typeinfo(arginfo)  # self.determine_unserializers(arginfo)
                self.infomap[index] = name, arginfo, argnames, converters, category

                if dec.get("flags_value"):
                    self.flags_value[name] = {}
                    for arg, values in dec["flags_value"].items():
                        self.flags_value[name][arg] = dict(values)

                if dec.get("flags_bitmask"):
                    self.flags_bitmask[name] = {}
                    for arg, values in dec["flags_bitmask"].items():
                        self.flags_bitmask[name][arg] = values
                    continue

            elif mtype == "debug":
                log.info("Debug message from monitor: " "{0}".format(dec.get("msg", "")))

            elif mtype == "new_process":
                # new_process message from VMI monitor.
                vmtime = datetime.datetime.fromtimestamp(dec.get("starttime", 0))
                procname = dec.get("name", "NONAME")
                ppid = 0
                modulepath = "DUMMY"

                self.fd.log_process(context, vmtime, None, ppid, modulepath, procname)

            else:
                # Regular api call.
                if index not in self.infomap:
                    log.warning("Got API with unknown index - monitor needs " "to explain first: {0}".format(dec))
                    return True

                apiname, arginfo, argnames, converters, category = self.infomap[index]
                args = dec.get("args", [])

                if len(args) != len(argnames):
                    log.warning("Inconsistent arg count (compared to arg names) " "on %s: %s names %s", dec, argnames, apiname)
                    continue

                argdict = dict((argnames[i], converters[i](args[i])) for i in range(len(args)))

                if apiname == "__process__":
                    # Special new process message from cuckoomon.
                    timelow = argdict["TimeLow"] & 0xFFFFFFFF
                    timehigh = argdict["TimeHigh"] & 0xFFFFFFFF
                    # FILETIME is 100-nanoseconds from 1601 :/
                    vmtimeunix = timelow + (timehigh << 32)
                    vmtimeunix = vmtimeunix / 10000000.0 - 11644473600
                    vmtime = datetime.datetime.fromtimestamp(vmtimeunix)

                    pid = argdict["ProcessIdentifier"]
                    ppid = argdict["ParentProcessIdentifier"]
                    modulepath = argdict["ModulePath"]
                    procname = get_filename_from_path(modulepath)

                    self.fd.log_process(context, vmtime, pid, ppid, modulepath, procname)
                    return True

                elif apiname == "__thread__":
                    pid = argdict["ProcessIdentifier"]
                    self.fd.log_thread(context, pid)
                    return True
                elif apiname == "__environ__":
                    self.fd.log_environ(context, argdict)
                    return True

                # elif apiname == "__anomaly__":
                # tid = argdict["ThreadIdentifier"]
                # subcategory = argdict["Subcategory"]
                # msg = argdict["Message"]
                # self.fd.log_anomaly(subcategory, tid, msg)
                # return True

                context[2] = argdict.pop("is_success", 1)
                context[3] = argdict.pop("retval", 0)
                arguments = list(argdict.items())
                arguments += list(dec.get("aux", {}).items())

                self.fd.log_call(context, apiname, category, arguments)

            return True
