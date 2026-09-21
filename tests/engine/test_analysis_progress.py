from memscope_engine.analysis.progress import AnalysisProgress, heartbeat_tau, step_ranges


def test_handles_owns_most_of_the_full_analysis_bar() -> None:
    ids = [
        "processes",
        "session",
        "command_lines",
        "modules",
        "network",
        "handles",
        "findings",
        "iocs",
        "timeline",
    ]
    ranges = step_ranges(ids)
    lo, hi = ranges["handles"]
    assert lo < 55
    assert hi - lo > 30
    assert abs(ranges["timeline"][1] - 100.0) < 0.05
    assert ranges["processes"][1] < 20


def test_analysis_progress_emits_weighted_percent() -> None:
    events: list[dict] = []

    def progress(msg: str, extra=None) -> None:
        events.append({"msg": msg, **(extra or {})})

    tracker = AnalysisProgress(progress, ["processes", "handles"])
    tracker.emit("processes", "Processes", frac=0)
    tracker.emit("handles", "Handles", frac=0)
    percents = [e["percent"] for e in events]
    assert percents[0] < 30
    assert percents[1] > percents[0]
    assert percents[1] < 70


def test_processes_only_owns_the_full_bar() -> None:
    ranges = step_ranges(["processes"])
    assert ranges["processes"][0] == 0.0
    assert abs(ranges["processes"][1] - 100.0) < 0.05


def test_heartbeat_tau_does_not_stretch_with_bar_span() -> None:
    solo = heartbeat_tau("processes", step_count=1)
    full = heartbeat_tau("processes", step_count=10)
    assert solo <= 50.0
    assert full > solo
    assert abs(full - (80.0 + 14 * 3.2)) < 0.01
