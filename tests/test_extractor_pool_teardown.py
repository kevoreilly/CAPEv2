import os
import time
import multiprocessing as mp


def _busy(_):
    time.sleep(60)


def test_extractor_pool_is_swept_by_killpg(tmp_path):
    """A child that creates the extractor pool and is killpg'd must leave no survivors."""
    marker = str(tmp_path / "epool_child")

    def child():
        os.setsid()
        open(marker, "w").close()
        import pebble
        ctx = mp.get_context("fork")  # spike decision: fork from warm child
        pool = pebble.ProcessPool(max_workers=2, context=ctx)
        for _ in range(2):
            pool.schedule(_busy, args=(1,), timeout=60)
        time.sleep(60)

    pid = os.fork()
    if pid == 0:
        try:
            child()
        finally:
            os._exit(0)
    while not os.path.exists(marker):
        time.sleep(0.05)
    time.sleep(1)
    os.killpg(pid, 15)
    time.sleep(2)
    # Reap the direct child's zombie so pgrep only sees actual survivors.
    try:
        os.waitpid(pid, os.WNOHANG)
    except ChildProcessError:
        pass
    import subprocess
    out = subprocess.run(["pgrep", "-g", str(pid)], capture_output=True, text=True)
    assert out.stdout.strip() == "", "extractor sub-pool survived killpg"
