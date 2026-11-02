"""Exercise PyMongo's real TLS parsing without opening a network connection."""
import importlib.util
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

import certifi
import dns.resolver
import dns.rrset
import pymongo
import pytest
from pymongo.database import Database

import dev_utils
from lib.cuckoo.common.dictionary import Dictionary


@pytest.fixture
def mongo_connection(monkeypatch):
    clients = []
    options = []
    pings = []

    def client_factory(**kwargs):
        options.append(kwargs.copy())
        kwargs["connect"] = False
        client = pymongo.MongoClient(**kwargs)
        clients.append(client)
        if kwargs["host"].startswith("mongodb+srv://") and getattr(type(client), "_resolve_srv", None):
            # PyMongo 4.15+ defers SRV parsing with connect=False. Resolve the
            # patched DNS records and initialize state, but do not open topology
            # monitors or a connection just to inspect the resulting SSL context.
            client._resolve_srv()
            client._init_background()
        return client

    monkeypatch.setattr(Database, "command", lambda self, command: pings.append(command))
    # Import under the package namespace so the relative mongo_hooks import works,
    # without reloading or replacing the suite's shared dev_utils.mongodb module.
    hooks = ModuleType("dev_utils.mongo_hooks")
    monkeypatch.setitem(sys.modules, "dev_utils.mongo_hooks", hooks)
    monkeypatch.setattr(dev_utils, "mongo_hooks", hooks, raising=False)

    def connect(settings):
        reporting = SimpleNamespace(mongodb=Dictionary(enabled=True, **settings))
        monkeypatch.setattr("lib.cuckoo.common.config.Config", lambda *args, **kwargs: reporting)
        name = "dev_utils._mongodb_tls_test"
        path = Path(__file__).resolve().parents[1] / "dev_utils" / "mongodb.py"
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        monkeypatch.setitem(sys.modules, name, module)
        spec.loader.exec_module(module)
        monkeypatch.setattr(module, "MongoClient", client_factory)
        return module.connect_to_mongo(), options, pings

    yield connect
    for client in clients:
        client.close()


@pytest.mark.parametrize(
    "settings, encrypted",
    [
        ({}, False),
        ({"tlscafile": certifi.where()}, True),
        ({"host": "mongodb://localhost/?tls=true"}, True),
        ({"host": "mongodb://localhost/?tls=false"}, False),
        ({"tls": "yes"}, True),
        ({"tls": "no"}, False),
        ({"tls": True}, True),
        ({"tls": False}, False),
        ({"tls": "no", "host": "mongodb://localhost/?tls=true"}, False),
        ({"tls": "yes", "host": "mongodb://localhost/?tls=false"}, True),
    ],
)
def test_mongodb_preserves_tls_inference_and_explicit_precedence(mongo_connection, settings, encrypted):
    client, options, pings = mongo_connection(settings)
    assert client is not None
    assert (client.options.pool_options._ssl_context is not None) is encrypted
    assert ("tls" in options[0]) is ("tls" in settings)
    assert pings == ["ping"]


@pytest.mark.parametrize("explicit, encrypted", [(None, True), ("no", False), ("yes", True)])
def test_mongodb_preserves_srv_tls_default(mongo_connection, monkeypatch, explicit, encrypted):
    def resolve(name, record_type, **kwargs):
        if record_type == "TXT":
            raise dns.resolver.NoAnswer()
        assert record_type == "SRV"
        return dns.rrset.from_text(name, 60, "IN", "SRV", "0 0 27017 mongo.example.test.")

    monkeypatch.setattr(dns.resolver, "resolve", resolve)
    settings = {"host": "mongodb+srv://cluster.example.test/"}
    if explicit is not None:
        settings["tls"] = explicit
    client, options, pings = mongo_connection(settings)
    assert client is not None
    assert (client.options.pool_options._ssl_context is not None) is encrypted
    assert ("tls" in options[0]) is (explicit is not None)
    assert pings == ["ping"]


def test_mongodb_does_not_silently_override_explicit_no_with_ca(mongo_connection, caplog):
    client, options, pings = mongo_connection({"tls": "no", "tlscafile": certifi.where()})
    assert client is None
    assert options[0]["tls"] is False
    assert "tls" in caplog.text.lower()
    assert pings == []
