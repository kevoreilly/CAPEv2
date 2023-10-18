import glob
import importlib
import inspect
import os
import pkgutil
from pathlib import Path


def ratdecodedr_load_decoders(path: str):
    from malwareconfig.common import Decoder

    dec_modules = {}
    # Walk recursively through all modules and packages.
    for loader, module_name, ispkg in pkgutil.walk_packages(path, "modules.processing.parsers.RATDecoders."):
        # If current item is a package, skip.
        if ispkg:
            continue
        # Try to import the module, otherwise skip.
        try:
            module = importlib.import_module(module_name)
        except ImportError as e:
            print(f"Unable to import Module {module_name}: {e}")
            continue

        for mod_name, mod_object in inspect.getmembers(module):
            if inspect.isclass(mod_object) and issubclass(mod_object, Decoder) and mod_object is not Decoder:
                dec_modules[mod_object.decoder_name] = dict(
                    obj=mod_object,
                    decoder_name=mod_object.decoder_name,
                    decoder_description=mod_object.decoder_description,
                    decoder_version=mod_object.decoder_version,
                    decoder_author=mod_object.decoder_author,
                )
    return dec_modules


def cape_load_decoders(CUCKOO_ROOT: str):

    cape_modules = {}
    cape_decoders = os.path.join(CUCKOO_ROOT, "modules", "processing", "parsers", "CAPE")
    CAPE_DECODERS = {"cape": [os.path.basename(decoder)[:-3] for decoder in glob.glob(f"{cape_decoders}/[!_]*.py")]}

    custom_cape_decoders = os.path.join(CUCKOO_ROOT, "custom", "parsers")
    CAPE_DECODERS.setdefault("custom", []).extend(
        [os.path.basename(decoder)[:-3] for decoder in glob.glob(f"{custom_cape_decoders}/[!_]*.py")]
    )

    versions = {
        "cape": "modules.processing.parsers.CAPE",
        "custom": "custom.parsers",
    }

    for version, names in CAPE_DECODERS.items():
        for name in names:
            try:
                # The name of the module must match what's given as the cape_type for yara
                # hits with the " Config", " Payload", or " Loader" ending removed and with  spaces replaced with underscores.
                # For example, a cape_type of "Emotet Payload" would trigger a config parser named "Emotet.py".
                cape_modules[name.replace("_", " ")] = importlib.import_module(f"{versions[version]}.{name}")
            except (ImportError, IndexError, AttributeError) as e:
                print(f"CAPE parser: No module named {name} - {e}")
            except SyntaxError as e:
                print(f"CAPE parser: Fix your code in {name} - {e}")
            except Exception as e:
                print(f"CAPE parser: Fix your code in {name} - {e}")

    return cape_modules


def malduck_load_decoders(CUCKOO_ROOT: str):

    malduck_modules = {}
    malduck_decoders = os.path.join(CUCKOO_ROOT, "modules", "processing", "parsers", "malduck")
    MALDUCK_DECODERS = [os.path.basename(decoder)[:-3] for decoder in glob.glob(f"{malduck_decoders}/[!_]*.py")]

    for name in MALDUCK_DECODERS:
        try:
            malduck_modules[name] = importlib.import_module(f"modules.processing.parsers.malduck.{name}")
        except (ImportError, IndexError) as e:
            print(f"malduck parser: No module named {name} - {e}")

    return malduck_modules


def file_extra_info_load_modules(CUCKOO_ROOT: str):
    file_extra_modules = []
    extra_modules = os.path.join(CUCKOO_ROOT, "lib", "cuckoo", "common", "integrations", "file_extra_info_modules")
    if not Path(extra_modules).exists():
        return []

    EXTRA_MODULES = [os.path.basename(decoder)[:-3] for decoder in glob.glob(f"{extra_modules}/[!_]*.py")]

    for name in EXTRA_MODULES:
        try:
            module = importlib.import_module(f"lib.cuckoo.common.integrations.file_extra_info_modules.{name}")
            if not getattr(module, "enabled", False):
                continue
            file_extra_modules.append(module)
        except (ImportError, IndexError, AttributeError) as e:
            print(f"file_extra_info module: No module named {name} - {e}")

    return file_extra_modules
