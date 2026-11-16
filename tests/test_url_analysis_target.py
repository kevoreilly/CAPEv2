from types import SimpleNamespace


def _processor(monkeypatch, task, results):
    import modules.processing.url_analysis as url_analysis

    monkeypatch.setattr(url_analysis, "HAVE_WHOIS", False)
    monkeypatch.setattr(url_analysis, "HAVE_VIRUSTOTAL", False)
    processor = url_analysis.UrlAnalysis(results)
    processor.set_task(task)
    processor.set_options(SimpleNamespace(whois=False))
    return processor


def test_url_analysis_adds_submitted_url_to_target(monkeypatch):
    url = "https://example.com/path"
    results = {}
    processor = _processor(monkeypatch, {"category": "url", "target": url}, results)

    assert processor.run() == {"url": url}
    assert results["target"] == {"category": "url", "url": url}


def test_url_analysis_does_not_overwrite_non_url_target(monkeypatch):
    target = {"category": "file", "file": {"sha256": "abc"}}
    results = {"target": target}
    processor = _processor(monkeypatch, {"category": "file", "target": "/tmp/sample"}, results)

    assert processor.run() == {}
    assert results["target"] is target
