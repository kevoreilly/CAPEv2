"""Pure-logic unit tests for central mode — no Django / pymongo / CAPE web imports
(the web layer is iterated live on a CAPE box). Run: pytest tests/test_central_mode.py"""
import os

import pytest

from lib.cuckoo.common.central_mode import _parse, _as_bool, _as_int, _as_port, upload_target_realpath
from lib.cuckoo.common.central_guac import (
    _libvirt_ssh_dsn,
    _worker_api_token,
    _worker_task_view_url,
)
from lib.cuckoo.common.hunt_query import build_hunt_facets
from lib.cuckoo.common.storage_backend import (
    ArtifactNotFound,
    LocalFSStore,
    S3Store,
    get_artifact_store,
)
from lib.cuckoo.common.job_directory import (
    BrokerHttpJobDirectory,
    DynamoJobDirectory,
    JobLocation,
    get_job_directory,
    loc_from_item,
)


def test_as_bool():
    assert _as_bool("yes") is True
    assert _as_bool("on") is True
    assert _as_bool("no") is False
    assert _as_bool(None, False) is False
    assert _as_bool(True) is True


def test_as_int():
    assert _as_int("42", 0) == 42
    assert _as_int(7, 0) == 7
    assert _as_int("  9443 ", 0) == 9443  # stripped
    assert _as_int(None, 8000) == 8000
    assert _as_int("notaport", 8000) == 8000  # garbage -> default, no crash


def test_as_port():
    assert _as_port("9443", 8000) == 9443
    assert _as_port(443, 8000) == 443
    # int() accepts these but they're not real ports -> fall back to the default (not a broken URL)
    assert _as_port("0", 8000) == 8000
    assert _as_port("-1", 8000) == 8000
    assert _as_port("99999", 8000) == 8000
    assert _as_port("nope", 8000) == 8000


def test_central_mode_defaults_off():
    c = _parse({})
    assert c.enabled is False
    assert c.s3_bucket == ""
    assert c.s3_prefix == "results"


def test_central_mode_on():
    c = _parse({"enabled": "yes", "s3_bucket": "b", "s3_region": "us-east-1", "s3_prefix": "results"})
    assert c.enabled is True
    assert c.s3_bucket == "b"


def test_central_mode_backend_fields_parse():
    # The new backend-selection fields (the only thing that made the store AWS-locked)
    # parse from [central_mode], with sane defaults when absent.
    d = _parse({})
    assert d.storage_backend == "s3"
    assert d.s3_endpoint_url == "" and d.s3_access_key == "" and d.s3_secret_key == ""
    assert d.central_local_root == ""
    c = _parse({
        "enabled": "yes",
        "storage_backend": "LOCAL",  # normalized to lower
        "s3_endpoint_url": "https://minio.local:9000",
        "s3_access_key": "ak",
        "s3_secret_key": "sk",
        "central_local_root": "/srv/cape-central",
    })
    assert c.storage_backend == "local"
    assert c.s3_endpoint_url == "https://minio.local:9000"
    assert c.s3_access_key == "ak" and c.s3_secret_key == "sk"
    assert c.central_local_root == "/srv/cape-central"


def test_get_artifact_store_single_node_is_local_fs():
    store, is_central = get_artifact_store(_parse({}))
    assert is_central is False
    assert isinstance(store, LocalFSStore)
    # single-node always reads the local storage/analyses tree
    assert store.base_dir.endswith(os.path.join("storage", "analyses"))


def test_get_artifact_store_central_s3():
    store, is_central = get_artifact_store(
        _parse({"enabled": "yes", "s3_bucket": "bkt", "s3_region": "eu-west-1"})
    )
    assert is_central is True
    assert isinstance(store, S3Store)
    assert store.bucket == "bkt" and store.region == "eu-west-1"
    # endpoint/creds default to None so boto3 uses AWS's endpoint + default cred chain
    assert store.endpoint_url is None and store.access_key is None and store.secret_key is None


def test_get_artifact_store_central_minio_endpoint():
    store, _ = get_artifact_store(
        _parse({
            "enabled": "yes", "s3_bucket": "bkt",
            "s3_endpoint_url": "https://minio.local:9000",
            "s3_access_key": "ak", "s3_secret_key": "sk",
        })
    )
    assert isinstance(store, S3Store)
    assert store.endpoint_url == "https://minio.local:9000"
    assert store.access_key == "ak" and store.secret_key == "sk"


def test_get_artifact_store_central_local_mount(tmp_path):
    root = str(tmp_path / "central")
    store, is_central = get_artifact_store(
        _parse({"enabled": "yes", "storage_backend": "local", "central_local_root": root})
    )
    assert is_central is True
    assert isinstance(store, LocalFSStore)
    assert store.base_dir == root


def test_get_artifact_store_local_backend_without_root_falls_back_to_s3():
    # storage_backend=local but no central_local_root is a misconfig; it must NOT
    # silently read the single-node tree — it falls through to the S3 store (whose
    # missing-bucket prereq centralstore validates up front).
    store, is_central = get_artifact_store(
        _parse({"enabled": "yes", "storage_backend": "local", "s3_bucket": "bkt"})
    )
    assert is_central is True
    assert isinstance(store, S3Store)


def test_localfsstore_roundtrip(tmp_path):
    # LocalFSStore backs BOTH single-node and central-on-a-shared-mount, so its
    # round-trip is the contract the read+write seams depend on.
    base = str(tmp_path / "base")
    store = LocalFSStore(base)
    container = "results/job-1"

    src = tmp_path / "src.txt"
    src.write_text("hello world")
    store.put_file(str(src), container, "reports/report.json")

    assert store.exists(container, "reports/report.json") is True
    assert store.exists(container, "missing") is False

    body_iter, length = store.stream(container, "reports/report.json")
    assert b"".join(body_iter) == b"hello world"
    assert length == len("hello world")

    assert store.read_text(container, "reports/report.json", 1000) == "hello world"
    assert store.read_text(container, "missing", 1000) == ""

    path, is_temp = store.materialize(container, "reports/report.json")
    assert is_temp is False and os.path.exists(path)
    assert store.materialize(container, "missing") == (None, False)

    assert list(store.iter_relpaths(container)) == ["reports/report.json"]

    dest = tmp_path / "out" / "copy.json"
    store.download(container, "reports/report.json", str(dest))
    assert dest.read_text() == "hello world"


def test_localfsstore_stream_missing_raises(tmp_path):
    store = LocalFSStore(str(tmp_path))
    with pytest.raises(ArtifactNotFound):
        store.stream("results/job-x", "nope")


def test_s3store_is_lazy_no_client_on_construct():
    # Constructing the store must NOT build a boto3 client (so import/config never
    # touches the network); the client is built on first op.
    store = S3Store("bkt", "us-east-1")
    assert store._cli is None


# ---- Phase 2: job->worker directory (interactive guac routing) ----

def test_central_mode_job_directory_fields_parse():
    d = _parse({})
    assert d.job_directory == "broker_http"  # default backend (vendor-neutral)
    assert d.broker_url == "" and d.broker_api_token == ""
    c = _parse({
        "enabled": "yes",
        "job_directory": "BROKER_HTTP",  # normalized to lower
        "broker_url": "https://broker.local",
        "broker_api_token": "tok",
    })
    assert c.job_directory == "broker_http"
    assert c.broker_url == "https://broker.local" and c.broker_api_token == "tok"


def test_loc_from_item_maps_and_normalizes():
    # the broker record (DynamoDB item OR broker HTTP status body) -> JobLocation
    loc = loc_from_item({"sandbox_worker_ip": "10.0.0.5", "cape_task_id": 42, "status": "running"})
    assert loc == JobLocation("10.0.0.5", 42)
    # cape_task_id may legitimately be 0 (distinct from absent); worker_ip "" -> None
    assert loc_from_item({"sandbox_worker_ip": "", "cape_task_id": 0}) == JobLocation(None, 0)
    assert loc_from_item({}) == JobLocation(None, None)
    assert loc_from_item(None) == JobLocation(None, None)
    # IPv6 is a valid IP too (kept as-is)
    assert loc_from_item({"sandbox_worker_ip": "fd00::1", "cape_task_id": 5}) == JobLocation("fd00::1", 5)


def test_loc_from_item_rejects_non_ip_worker_ip():
    # sandbox_worker_ip becomes the netloc of a libvirt DSN + an authenticated apiv2 URL. A poisoned
    # broker record must NOT flow through: a non-IP value (injection payload, hostname, garbage) is
    # dropped to None so the caller keeps the localhost path — closes the DSN/URL-injection vector.
    payload = "1.2.3.4/system?keyfile=/attacker/key&no_verify=1&x="
    assert loc_from_item({"sandbox_worker_ip": payload, "cape_task_id": 7}) == JobLocation(None, 7)
    assert loc_from_item({"sandbox_worker_ip": "attacker.host:9999/x?a=", "cape_task_id": 1}) == JobLocation(None, 1)
    assert loc_from_item({"sandbox_worker_ip": "not-an-ip", "cape_task_id": 2}) == JobLocation(None, 2)
    # cape_task_id survives even when the IP is rejected (the job exists; it's just unroutable here)
    assert loc_from_item({"sandbox_worker_ip": "999.999.999.999", "cape_task_id": 0}) == JobLocation(None, 0)


def test_get_job_directory_off_returns_none():
    assert get_job_directory(_parse({})) is None  # central mode off
    # enabled but default backend (broker_http) with no broker_url -> None (caller keeps localhost)
    assert get_job_directory(_parse({"enabled": "yes"})) is None


def test_get_job_directory_default_is_broker_http():
    # default backend is now broker_http (vendor-neutral); with a broker_url it resolves to BrokerHttp
    d = get_job_directory(_parse({"enabled": "yes", "broker_url": "https://broker.local"}))
    assert isinstance(d, BrokerHttpJobDirectory)


def test_get_job_directory_dynamodb_explicit():
    # dynamodb is opt-in (AWS); must be selected explicitly now
    d = get_job_directory(_parse({"enabled": "yes", "job_directory": "dynamodb", "broker_table": "tbl", "s3_region": "eu-west-1"}))
    assert isinstance(d, DynamoJobDirectory)
    assert d.table == "tbl" and d.region == "eu-west-1"


def test_get_job_directory_broker_http():
    d = get_job_directory(_parse({
        "enabled": "yes", "job_directory": "broker_http",
        "broker_url": "https://broker.local/", "broker_api_token": "tok",
    }))
    assert isinstance(d, BrokerHttpJobDirectory)
    assert d.broker_url == "https://broker.local"  # trailing slash stripped
    assert d.token == "tok"


def test_get_job_directory_broker_http_without_url_returns_none():
    # broker_http selected but no broker_url -> None (caller keeps localhost path)
    assert get_job_directory(_parse({"enabled": "yes", "job_directory": "broker_http"})) is None


def test_broker_http_directory_no_url_lookup_none():
    assert BrokerHttpJobDirectory("").lookup("job-1") is None


def test_upload_target_realpath(tmp_path):
    # Layout: storage/{analyses/<id>, binaries, guacrecordings}; a sibling secret outside storage.
    storage = tmp_path / "storage"
    analysis = storage / "analyses" / "42"
    binaries = storage / "binaries"
    guac = storage / "guacrecordings"
    for d in (analysis, binaries, guac):
        d.mkdir(parents=True)
    secret = tmp_path / "secret.txt"
    secret.write_text("AWS_SECRET")
    blob = binaries / "deadbeef"
    blob.write_text("sample bytes")
    rec = guac / "42_sess"
    rec.write_text("guac dump")

    base_real = os.path.realpath(str(analysis))
    trusted = [os.path.realpath(str(binaries)), os.path.realpath(str(guac))]

    # a regular file inside the analysis tree -> uploaded (its own realpath)
    plain = analysis / "report.json"
    plain.write_text("{}")
    assert upload_target_realpath(str(plain), base_real, trusted) == os.path.realpath(str(plain))

    # the `binary` symlink -> resolves into storage/binaries (trusted) -> uploaded as the blob
    binlink = analysis / "binary"
    binlink.symlink_to(blob)
    assert upload_target_realpath(str(binlink), base_real, trusted) == os.path.realpath(str(blob))

    # a recording referenced via symlink into storage/guacrecordings (trusted) -> uploaded
    reclink = analysis / "guac.rec"
    reclink.symlink_to(rec)
    assert upload_target_realpath(str(reclink), base_real, trusted) == os.path.realpath(str(rec))

    # a sample-planted symlink to a host secret OUTSIDE storage roots -> skipped (None)
    evil = analysis / "evil"
    evil.symlink_to(secret)
    assert upload_target_realpath(str(evil), base_real, trusted) is None

    # prefix-collision guard: a sibling dir sharing a name prefix must NOT count as inside
    sibling = storage / "binaries-evil"
    sibling.mkdir()
    sneaky = sibling / "x"
    sneaky.write_text("nope")
    link2 = analysis / "sneaky"
    link2.symlink_to(sneaky)
    assert upload_target_realpath(str(link2), base_real, trusted) is None


def test_central_mode_worker_access_fields_parse():
    # Interactive-guac worker access: config-driven (was hardcoded deb paths in central_guac).
    d = _parse({})
    assert d.worker_api_token_file == "/etc/cape/api-token"
    assert d.worker_api_port == 8000 and isinstance(d.worker_api_port, int)
    assert d.worker_ssh_user == "cape"
    assert d.worker_ssh_keyfile == "/home/cape/.ssh/id_ed25519"
    c = _parse({
        "worker_api_token_file": "/opt/secrets/tok",
        "worker_api_port": "9443",   # string in conf -> int
        "worker_ssh_user": "sandbox",
        "worker_ssh_keyfile": "/home/sandbox/.ssh/id_rsa",
    })
    assert c.worker_api_token_file == "/opt/secrets/tok"
    assert c.worker_api_port == 9443 and isinstance(c.worker_api_port, int)
    assert c.worker_ssh_user == "sandbox"
    assert c.worker_ssh_keyfile == "/home/sandbox/.ssh/id_rsa"
    # a bad/out-of-range port degrades to the default, not a startup crash or a broken URL
    assert _parse({"worker_api_port": "nope"}).worker_api_port == 8000
    assert _parse({"worker_api_port": "0"}).worker_api_port == 8000
    assert _parse({"worker_api_port": "99999"}).worker_api_port == 8000


def test_central_guac_worker_url_and_dsn():
    # port + task id substitute; the deb defaults no longer live in the code path
    assert _worker_task_view_url("10.0.0.5", 8000, 42) == "http://10.0.0.5:8000/apiv2/tasks/view/42/"
    assert _worker_task_view_url("10.0.0.5", "9443", "7") == "http://10.0.0.5:9443/apiv2/tasks/view/7/"
    # DSN carries the CONFIGURED user + keyfile (not hardcoded cape / id_ed25519)
    assert _libvirt_ssh_dsn("10.0.0.9", "cape", "/home/cape/.ssh/id_ed25519") == \
        "qemu+ssh://cape@10.0.0.9/system?keyfile=/home/cape/.ssh/id_ed25519&no_verify=1"
    assert _libvirt_ssh_dsn("10.0.0.9", "sandbox", "/home/sandbox/.ssh/id_rsa") == \
        "qemu+ssh://sandbox@10.0.0.9/system?keyfile=/home/sandbox/.ssh/id_rsa&no_verify=1"
    # a keyfile with a URI metachar is quoted so it can't corrupt the query string
    dsn = _libvirt_ssh_dsn("10.0.0.9", "cape", "/home/cape/my key&x")
    assert "my%20key%26x" in dsn and dsn.endswith("&no_verify=1")


def test_central_guac_worker_api_token(tmp_path):
    tok = tmp_path / "api-token"
    tok.write_text("  s3cr3t\n")
    assert _worker_api_token(str(tok)) == "s3cr3t"  # stripped
    # missing/unreadable -> "" (=> no auth header downstream), never raises
    assert _worker_api_token(str(tmp_path / "nope")) == ""


def test_centralstore_done_marker_local_and_uploaded(tmp_path):
    # The completion marker must be BOTH written locally (the worker's NVMe-cleanup gate) AND
    # uploaded to the central store (the read seam's .central_staged completion signal). Regression:
    # it was local-only, so artifact_storage._stage_tree never saw it and re-staged every view.
    from modules.reporting.centralstore import _emit_done_marker

    analysis = tmp_path / "analyses" / "77"
    analysis.mkdir(parents=True)
    store = LocalFSStore(str(tmp_path / "central"))
    cfg = _parse({"enabled": "yes", "s3_bucket": "bkt", "s3_prefix": "results"})
    container = "results/ui-77"

    _emit_done_marker(store, container, str(analysis), cfg, "ui-77", 12)

    # local marker present (cleanup gate) with the expected metadata ...
    local_marker = analysis / ".centralstore.done"
    assert local_marker.exists()
    import json
    meta = json.loads(local_marker.read_text())
    assert meta["job_id"] == "ui-77" and meta["artifacts"] == 12
    assert meta["location"] == "s3://bkt/results/ui-77/"
    # ... AND uploaded to the store under the exact key the read seam checks for
    assert store.exists(container, ".centralstore.done") is True


def test_centralstore_done_marker_upload_failure_keeps_local(tmp_path):
    # A store put_file failure must NOT raise (the artifacts are already durable) and must leave
    # the local marker intact so the worker's cleanup gate still fires.
    from modules.reporting.centralstore import _emit_done_marker

    analysis = tmp_path / "analyses" / "88"
    analysis.mkdir(parents=True)

    class BoomStore:
        def put_file(self, *a, **k):
            raise RuntimeError("s3 down")

    cfg = _parse({"enabled": "yes", "s3_bucket": "bkt"})
    _emit_done_marker(BoomStore(), "results/ui-88", str(analysis), cfg, "ui-88", 3)  # must not raise
    assert (analysis / ".centralstore.done").exists()


def test_hunt_facets_per_category_no_facet():
    sent = []

    def fake_agg(coll, pipeline):
        sent.append(pipeline)
        return [{"_id": "evil.com", "count": 5, "task_ids": [1, 2]}]

    facets = build_hunt_facets(
        fake_agg,
        match={"$and": [{}, {"info.visibility": "public"}]},
        hunt_map={"domains": {"db_unwind": "$network.domains", "db_group": "$network.domains.domain", "db_match": {"count": {"$gte": 1}}}},
        categories={"domains": True},
        min_count=1,
    )
    assert not any(any("$facet" in stage for stage in p) for p in sent)
    assert sent[0][0] == {"$match": {"$and": [{}, {"info.visibility": "public"}]}}
    assert facets["domains"][0]["_id"] == "evil.com"
