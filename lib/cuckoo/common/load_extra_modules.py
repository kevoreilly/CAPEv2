import glob
import importlib
import inspect
import os
import pkgutil
from pathlib import Path

from lib.cuckoo.common.config import Config

selfextract_conf = Config("selfextract")


def ratdecodedr_load_decoders(path: str):
    """
    Loads and returns a dictionary of RAT decoder modules from the specified path.

    This function walks recursively through all modules and packages in the given path,
    imports them, and collects classes that are subclasses of the `Decoder` class from
    the `malwareconfig.common` module. It skips packages and handles import errors gracefully.

    Args:
        path (str): The path to the directory containing the RAT decoder modules.

    Returns:
        dict: A dictionary where the keys are decoder names and the values are dictionaries
            containing the following information about each decoder:
            - obj: The decoder class object.
            - decoder_name: The name of the decoder.
            - decoder_description: A description of the decoder.
            - decoder_version: The version of the decoder.
            - decoder_author: The author of the decoder.
    """
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


def cape_load_custom_decoders(CUCKOO_ROOT: str):
    """
    Loads custom decoders for CAPE from specified directories within the CUCKOO_ROOT path.

    This function searches for Python modules in the "modules/processing/parsers/CAPE" and
    "custom/parsers" directories within the CUCKOO_ROOT path. It imports these modules and
    stores them in a dictionary where the keys are the module names with spaces replaced by
    underscores, and the values are the imported modules.

    Args:
        CUCKOO_ROOT (str): The root directory of the CUCKOO installation.

    Returns:
        dict: A dictionary where the keys are the names of the decoders and the values are
            the imported modules.

    Raises:
        ImportError: If a module cannot be imported.
        IndexError: If there is an indexing error during module import.
        AttributeError: If there is an attribute error during module import.
        SyntaxError: If there is a syntax error in the module code.
        Exception: For any other exceptions that occur during module import.
    """

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
    """
    Loads and imports malduck decoder modules from the specified CUCKOO_ROOT directory.

    Args:
        CUCKOO_ROOT (str): The root directory of the CUCKOO installation.

    Returns:
        dict: A dictionary where the keys are the names of the decoder modules and the values are the imported module objects.

    Raises:
        ImportError: If a module cannot be imported.
        IndexError: If there is an issue with the module name.
    """

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
    """
    Loads extra file information modules from the specified CUCKOO_ROOT directory.

    This function searches for Python modules in the "file_extra_info_modules" directory
    within the given CUCKOO_ROOT path. It imports and returns a list of modules that are
    enabled based on their internal configuration or the selfextract_conf settings.

    Args:
        CUCKOO_ROOT (str): The root directory of the CUCKOO installation.

    Returns:
        list: A list of imported modules that are enabled. If the directory does not exist,
            an empty list is returned.

    Raises:
        ImportError: If a module cannot be imported.
        IndexError: If there is an indexing error during module import.
        AttributeError: If an attribute is missing during module import.
    """
    file_extra_modules = []
    extra_modules = os.path.join(CUCKOO_ROOT, "lib", "cuckoo", "common", "integrations", "file_extra_info_modules")
    if not Path(extra_modules).exists():
        return []

    EXTRA_MODULES = [os.path.basename(decoder)[:-3] for decoder in glob.glob(f"{extra_modules}/[!_]*.py")]

    for name in EXTRA_MODULES:
        try:
            module = importlib.import_module(f"lib.cuckoo.common.integrations.file_extra_info_modules.{name}")
            if not getattr(module, "enabled", False) and not selfextract_conf.__dict__.get(name, {}).get("enabled", False):
                continue
            file_extra_modules.append(module)
        except (ImportError, IndexError, AttributeError) as e:
            print(f"file_extra_info module: No module named {name} - {e}")

    return file_extra_modules
