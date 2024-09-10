import time
from dataclasses import dataclass, field


@dataclass
class Counter:
    """Profiler that counts real and CPU time."""

    real: float = field(default_factory=time.perf_counter)
    cpu: float = field(default_factory=time.process_time)

    def __sub__(self, other):
        real = self.real - other.real
        cpu = self.cpu - other.cpu
        return Counter(real, cpu)

    def __add__(self, other):
        real = self.real + other.real
        cpu = self.cpu + other.cpu
        return Counter(real, cpu)

    def __str__(self) -> str:
        return f"{self.real:.2f}s (cpu {self.cpu:.2f}s)".format(self.real, self.cpu)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, exc_tb):
        elapsed = Counter() - self
        self.__dict__.update(**elapsed.__dict__)
