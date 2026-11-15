"""Totals of the relay process in the Prometheus text format, with no label of an identity."""

from collections import Counter
from collections.abc import Mapping

# Shown as 0 before they first move.
PLAIN_COUNTERS = (
    "sotto_logins_total",
    "sotto_messages_stored_total",
    "sotto_messages_delivered_total",
    "sotto_messages_acked_total",
    "sotto_messages_expired_total",
)
LABELLED_COUNTERS = (
    "sotto_frames_total",
    "sotto_bundle_fetches_total",
    "sotto_limit_refusals_total",
)


class Metrics:
    """The counters of the process; the gauges are read when the metrics are rendered."""

    def __init__(self) -> None:
        self.samples: Counter[str] = Counter(dict.fromkeys(PLAIN_COUNTERS, 0))

    def count(self, name: str, amount: int = 1, **labels: str) -> None:
        pairs = ",".join(f'{label}="{value}"' for label, value in labels.items())
        sample = f"{name}{{{pairs}}}" if pairs else name
        self.samples[sample] += amount

    def render(self, gauges: Mapping[str, int]) -> str:
        lines = []
        for name, value in gauges.items():
            lines += [f"# TYPE {name} gauge", f"{name} {value}"]
        for name in (*PLAIN_COUNTERS, *LABELLED_COUNTERS):
            lines.append(f"# TYPE {name} counter")
            samples = sorted(
                sample for sample in self.samples if sample.partition("{")[0] == name
            )
            lines += [f"{sample} {self.samples[sample]}" for sample in samples]
        return "\n".join(lines) + "\n"
