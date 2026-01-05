from unittest.mock import patch, Mock
import logging
from logging import StreamHandler
import pytest

from lib.common.results import NetlogHandler
import lib.core.startup
import lib.core.config

import lib

@pytest.fixture
def patch_netloghandler(monkeypatch):
    monkeypatch.setattr(NetlogHandler, "__init__", Mock(return_value=None))
    monkeypatch.setattr(NetlogHandler, "connect", Mock())
    yield

@patch('os.makedirs')
@patch('os.path.exists')
def test_create_folders_path_not_exists(os_path_exists, os_mkdirs):
    """Test initial folder creation with paths that do not exist"""
    # Fake path not existing
    os_path_exists.return_value = False
    lib.core.startup.create_folders()
    assert os_path_exists.called
    # Ensure there is an attempt to create a folder
    assert os_mkdirs.called

@patch('os.makedirs')
@patch('os.path.exists')
def test_create_folders_path_exists(os_path_exists, os_mkdirs):
    """Test initial folder creation with paths that already exist"""
    # Fake path not existing
    os_path_exists.return_value = True
    lib.core.startup.create_folders()
    assert os_path_exists.called
    # Ensure there are no attempts to create a folder
    assert not os_mkdirs.called

@pytest.mark.usefixtures("patch_netloghandler")
@patch("logging.Logger.addHandler")
def test_init_logging(addhandler):
    """Ensure init_logging adds the right log handlers"""
    lib.core.startup.init_logging()
    handlers = []
    # Get a list of all the types of handlers that are being added
    for name, args, kwargs in addhandler.mock_calls:
        handlers = [*handlers, *[type(arg) for arg in args]]
    # Ensure there is a StreamHandler and a NetlogHandler
    assert StreamHandler in handlers
    assert NetlogHandler in handlers
    # Ensure log level is set to DEBUG
    assert lib.core.startup.log.level == logging.DEBUG
