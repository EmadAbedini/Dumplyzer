from datetime import datetime, timezone

from memscope_engine.observed_time import (
    OsTimeBounds,
    is_analysis_clock_event,
    is_plausible_module_load,
    keep_timeline_event,
    parse_observed_datetime,
)
from memscope_engine.volatility.normalize import _ts, normalize_dlllist


def test_parse_system_time_space_offset() -> None:
    dt = parse_observed_datetime("2026-09-02 11:23:09+00:00")
    assert dt is not None
    assert dt.year == 2026
    assert dt.month == 9
    assert dt.day == 2


def test_ts_drops_filetime_garbage_years() -> None:
    assert _ts(datetime(2257, 5, 20, 3, 23, 55, tzinfo=timezone.utc)) is None
    assert _ts(datetime(2969, 1, 8, 11, 23, 19, tzinfo=timezone.utc)) is None
    kept = _ts(datetime(2026, 9, 2, 11, 23, 8, tzinfo=timezone.utc))
    assert kept is not None
    assert kept.startswith("2026-09-02")


def test_normalize_dlllist_drops_insane_load_time() -> None:
    mods = normalize_dlllist(
        ["PID", "Process", "Base", "Size", "Name", "Path", "LoadCount", "LoadTime", "File output"],
        [
            [
                10716,
                "app.exe",
                "0x1",
                "0x2",
                "IMM32.DLL",
                "C:\\Windows\\System32\\IMM32.DLL",
                1,
                datetime(2257, 5, 20, 3, 23, 55, tzinfo=timezone.utc),
                "Disabled",
            ],
            [
                10716,
                "app.exe",
                "0x3",
                "0x4",
                "ntdll.dll",
                "C:\\Windows\\System32\\ntdll.dll",
                1,
                datetime(2026, 9, 2, 11, 20, 0, tzinfo=timezone.utc),
                "Disabled",
            ],
        ],
        evidence_id="e",
        analysis_run_id="a",
        process_id="p",
        pid_filter=10716,
        source_plugin="windows.dlllist",
    )
    by_name = {m["name"]: m["load_time"] for m in mods}
    assert by_name["IMM32.DLL"] is None
    assert by_name["ntdll.dll"] is not None
    assert by_name["ntdll.dll"].startswith("2026-09-02")


def test_module_load_rejects_before_process_and_after_dump() -> None:
    created = datetime(2026, 9, 1, 4, 10, 34, tzinfo=timezone.utc)
    bounds = OsTimeBounds(
        lower=datetime(2026, 8, 25, tzinfo=timezone.utc),
        upper=datetime(2026, 9, 2, 12, 23, 9, tzinfo=timezone.utc),
        create_by_pid={10716: created},
    )
    assert is_plausible_module_load("2026-09-01T04:10:37+00:00", 10716, bounds)
    assert is_plausible_module_load("2026-09-02T11:23:08+00:00", 10716, bounds)
    assert not is_plausible_module_load("2257-05-20T03:23:55+00:00", 10716, bounds)
    assert not is_plausible_module_load("2002-05-20T17:37:23+00:00", 10716, bounds)
    assert not keep_timeline_event(
        {
            "event_kind": "module_load",
            "event_time": "2256-11-21T23:58:36+00:00",
            "pid": 10716,
        },
        bounds,
    )
    assert keep_timeline_event(
        {
            "event_kind": "process_create",
            "event_time": "2026-09-01T04:10:34+00:00",
            "pid": 10716,
        },
        bounds,
    )


def test_is_analysis_clock_event() -> None:
    assert is_analysis_clock_event(
        {"time_precision": "analysis_time", "event_kind": "network_artifacts"}
    )
    assert is_analysis_clock_event({"time_precision": "exact", "event_kind": "pe_extraction"})
    assert is_analysis_clock_event({"time_precision": "ANALYSIS_TIME", "event_kind": "process_create"})
    assert not is_analysis_clock_event(
        {"time_precision": "observed", "event_kind": "process_create"}
    )
    assert not is_analysis_clock_event(
        {"time_precision": "unknown", "event_kind": "process_relationship"}
    )
