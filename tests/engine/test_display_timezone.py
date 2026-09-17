"""Display time zone is a frontend presentation preference.

Canonical timestamps stay UTC in storage, Volatility output, and reports.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FRONTEND = ROOT / "app" / "frontend" / "src"


def test_timezone_preference_is_iana_localstorage_key() -> None:
    prefs = (FRONTEND / "lib" / "preferences.ts").read_text(encoding="utf-8")
    assert 'dumplyzer.ui.timeZone' in prefs
    assert "systemTimeZone()" in prefs
    assert "isValidTimeZone" in prefs
    assert "UTC+3:30" not in prefs


def test_analysis_options_includes_timezone_not_a_wizard() -> None:
    dialog = (FRONTEND / "components" / "AnalysisOptionsDialog.tsx").read_text(
        encoding="utf-8"
    )
    app = (FRONTEND / "App.tsx").read_text(encoding="utf-8")
    assert "Time Zone" in dialog
    assert "TimeZoneSelect" in dialog
    assert "Stored timestamps and the original memory image are not modified." in dialog
    assert "onTimeZoneChange" in dialog
    assert 'engineCall<Job>("analysis.run"' in app
    assert "timeZone" not in app.split('engineCall<Job>("analysis.run"')[1].split(");")[0]


def test_timestamp_display_converts_only_in_ui() -> None:
    datetime_src = (FRONTEND / "lib" / "datetime.tsx").read_text(encoding="utf-8")
    assert "formatDisplayTimestamp" in datetime_src
    assert "parseTimestampInstant" in datetime_src
    assert "Naive ISO values (no offset) are treated as UTC" in datetime_src
    assert "Never mutates the stored value" in datetime_src
    assert "title={raw}" in datetime_src


def test_html_json_csv_keep_canonical_event_times() -> None:
    html = (ROOT / "engine" / "memscope_engine" / "export" / "html_report.py").read_text(
        encoding="utf-8"
    )
    csv_src = (ROOT / "engine" / "memscope_engine" / "export" / "csv_export.py").read_text(
        encoding="utf-8"
    )
    json_src = (ROOT / "engine" / "memscope_engine" / "export" / "json_export.py").read_text(
        encoding="utf-8"
    )
    assert "e.get(\"event_time\")" in html
    assert "format_html_time" in html
    assert "Generated at (UTC)" not in html
    assert '["Generated at"' in html
    assert "Europe/Amsterdam" not in html
    assert "timeZone" not in csv_src
    assert "event_time" in csv_src
    assert "generated_at" in json_src


def test_iana_conversion_differs_by_zone() -> None:
    node = shutil.which("node")
    if not node:
        raise AssertionError("node is required to verify IANA display conversion")
    script = r"""
const instant = new Date("2026-09-10T15:55:28Z");
function parts(tz) {
  const p = new Intl.DateTimeFormat("en-US", {
    timeZone: tz,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
    hourCycle: "h23",
  }).formatToParts(instant);
  const get = (t) => p.find((x) => x.type === t)?.value;
  return `${get("year")}-${get("month")}-${get("day")} ${get("hour")}:${get("minute")}:${get("second")}`;
}
const out = {
  utc: parts("UTC"),
  tehran: parts("Asia/Tehran"),
  newYork: parts("America/New_York"),
  amsterdam: parts("Europe/Amsterdam"),
};
process.stdout.write(JSON.stringify(out));
"""
    raw = subprocess.check_output([node, "-e", script], text=True)
    out = json.loads(raw)
    assert out["utc"] == "2026-09-10 15:55:28"
    # Iran standard time is UTC+3:30 (no DST since 2022).
    assert out["tehran"] == "2026-09-10 19:25:28"
    # America/New_York observes EDT (UTC-4) on 10 Sep 2026.
    assert out["newYork"] == "2026-09-10 11:55:28"
    # Europe/Amsterdam observes CEST (UTC+2) on 10 Sep 2026.
    assert out["amsterdam"] == "2026-09-10 17:55:28"
    assert len({out["utc"], out["tehran"], out["newYork"], out["amsterdam"]}) == 4
