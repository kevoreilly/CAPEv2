"""Abstract processing engine: drives the per-task lifecycle for autoprocess.
Concrete engines (pebble, prefork) differ only in worker isolation."""


class ProcessingEngine:
    def __init__(self, task_fn, worker_init, source, parallel, timeout):
        self.task_fn = task_fn        # task_fn(task) -> None: runs ONE task to completion
        self.worker_init = worker_init  # called in worker context (pool init / post-fork)
        self.source = source          # TaskSource
        self.parallel = parallel
        self.timeout = timeout

    def run(self):
        raise NotImplementedError
