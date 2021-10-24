import os
import glob
import importlib
import inspect
import pkgutil


def ratdecodedr_load_decoders(path):
    from malwareconfig.common import Decoder

    dec_modules = dict()
    # Walk recursively through all modules and packages.
    for loader, module_name, ispkg in pkgutil.walk_packages(path, "modules.processing.parsers.RATDecoders."):
        # If current item is a package, skip.
        if ispkg:
            continue
        # Try to import the module, otherwise skip.
        try:
            module = importlib.import_module(module_name)
        except ImportError as e:
            print("Unable to import Module {0}: {1}".format(module_name, e))
            continue

        for mod_name, mod_object in inspect.getmembers(module):
            if inspect.isclass(mod_object):
                if issubclass(mod_object, Decoder) and mod_object is not Decoder:
                    dec_modules[mod_object.decoder_name] = dict(obj=mod_object,
                                                                decoder_name=mod_object.decoder_name,
                                                                decoder_description=mod_object.decoder_description,
                                                                decoder_version=mod_object.decoder_version,
                                                                decoder_author=mod_object.decoder_author
                                                                )
    return dec_modules


def cape_load_decoders(CUCKOO_ROOT):

    cape_modules = dict()
    cape_decoders = os.path.join(CUCKOO_ROOT, "modules", "processing", "parsers", "CAPE")
    CAPE_DECODERS = [os.path.basename(decoder)[:-3] for decoder in glob.glob(cape_decoders + "/[!_]*.py")]

    for name in CAPE_DECODERS:
        try:
            cape_modules[name] = importlib.import_module("modules.processing.parsers.CAPE." + name)
        except (ImportError, IndexError) as e:
            if "datadirs" in str(e):
              print("You are using wrong pype32 library. pip3 uninstall pype32 && pip3 install -U pype32-py3")
            print("CAPE parser: No module named {} - {}".format(name, e))

    return cape_modules

def malduck_load_decoders(CUCKOO_ROOT):

    malduck_modules = dict()
    malduck_decoders = os.path.join(CUCKOO_ROOT, "modules", "processing", "parsers", "malduck")
    MALDUCK_DECODERS = [os.path.basename(decoder)[:-3] for decoder in glob.glob(malduck_decoders + "/[!_]*.py")]

    for name in MALDUCK_DECODERS:
        try:
            malduck_modules[name] = importlib.import_module("modules.processing.parsers.malduck." + name)
        except (ImportError, IndexError) as e:
            print("malduck parser: No module named {} - {}".format(name, e))

    return malduck_modules
