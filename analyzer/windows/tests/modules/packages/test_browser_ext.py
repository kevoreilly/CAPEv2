"""Tests for the packages that open a browser with the extension from extra/browser_extension."""

import logging
from unittest import mock

import pytest

from modules.packages import chromium_ext, firefox_ext

URL = "http://example.com/"


@pytest.fixture
def browser(monkeypatch):
    browser = mock.Mock()
    browser.open.return_value = True
    fake_webbrowser = mock.Mock()
    fake_webbrowser.get.return_value = browser
    for module in (firefox_ext, chromium_ext):
        monkeypatch.setattr(module, "webbrowser", fake_webbrowser)
        monkeypatch.setattr(module, "time", mock.Mock())
    return browser


@pytest.mark.parametrize("package_class", [firefox_ext.Firefox_Ext, chromium_ext.ChromiumExt])
def test_start_returns_no_pids(package_class, browser):
    """webbrowser.open() returns a bool, which the analyzer would track as PID 1 and end the analysis."""
    package = package_class(options={})
    package.get_path = mock.Mock(return_value="browser.exe")
    assert package.start(URL) is None
    browser.open.assert_called_with(URL)


def test_firefox_ext_without_user_agent(browser, caplog):
    package = firefox_ext.Firefox_Ext(options={})
    package.get_path = mock.Mock(return_value="firefox.exe")
    with caplog.at_level(logging.ERROR):
        package.start(URL)
    assert "Invalid base64 encoded user agent" not in caplog.text


def test_firefox_ext_invalid_user_agent(browser, caplog):
    package = firefox_ext.Firefox_Ext(options={"user_agent": "not base64!"})
    package.get_path = mock.Mock(return_value="firefox.exe")
    with caplog.at_level(logging.ERROR):
        package.start(URL)
    assert "Invalid base64 encoded user agent" in caplog.text
