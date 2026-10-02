from lib.cuckoo.core.processing_engine.base import ProcessingEngine


def get_engine(name, **kwargs):
    """Construct the named engine. Imports are local so that selecting one engine
    never imports the other's dependencies."""
    if name == "pebble":
        from lib.cuckoo.core.processing_engine.pebble import PebbleEngine
        return PebbleEngine(**kwargs)
    if name == "prefork":
        from lib.cuckoo.core.processing_engine.prefork import PreforkEngine
        return PreforkEngine(**kwargs)
    raise ValueError("unknown processing engine: %r" % name)


__all__ = ["ProcessingEngine", "get_engine"]
