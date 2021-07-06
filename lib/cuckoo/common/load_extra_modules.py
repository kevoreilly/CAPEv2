import importlib
import inspect
import pkgutil


def ratdecodedr_load_decoders(path):
    from malwareconfig.common import Decoder
    from malwareconfig import decoders

    dec_modules = dict()

    # Walk recursively through all modules and packages.
    for loader, module_name, ispkg in pkgutil.walk_packages(path, decoders.__name__ + '.'):
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


def cape_load_decoders(path):
    cape_modules = dict()
    for _, module_name, ispkg in pkgutil.iter_modules([path], prefix=path.replace("/", ".")):
        if ispkg:
            continue
        # Try to import the module, otherwise skip.
        try:
            module = importlib.import_module(module_name)
        except ImportError as e:
            print("Unable to import Module {0}: {1}".format(module_name, e))
            continue

        cape_modules[module_name.split(".")[-1]] = module
    return cape_modules
