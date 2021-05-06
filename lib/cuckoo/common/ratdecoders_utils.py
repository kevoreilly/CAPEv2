import importlib
import inspect
import pkgutil

from malwareconfig.common import Decoder
from malwareconfig import decoders

"""
>>> from malwareconfig import decoders
>>> decoders.__name__
'malwareconfig.decoders'
>>> import pkgutil
>>> decoders.__path__
['/usr/local/lib/python3.8/dist-packages/malwareconfig/decoders']
"""
def load_decoders(path):

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
