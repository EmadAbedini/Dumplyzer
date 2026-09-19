from memscope_engine.errors import AppError, rpc_error_payload


def test_rpc_error_payload_keeps_app_message() -> None:
    err = AppError(
        code="region_missing",
        message="Memory region not found.",
        details="C:\\Users\\Rootman\\engine\\memory_artifacts.py:171",
        suggestion="Re-run VAD scan for this process, then retry extraction.",
        entity="memory",
    )
    payload = rpc_error_payload(err)
    assert payload["message"] == "Memory region not found."
    assert payload["data"]["app_code"] == "region_missing"
    assert payload["data"]["suggestion"]
    assert "details" not in payload["data"]
    assert "traceback" not in payload["data"]


def test_rpc_error_payload_hides_unexpected_exceptions() -> None:
    payload = rpc_error_payload(RuntimeError("memscope_engine.analysis.foo exploded"))
    assert payload["message"] == "Something went wrong."
    assert payload["data"]["app_code"] == "internal_error"
    assert "details" not in payload["data"]
    assert "traceback" not in payload["data"]
    assert "memscope_engine" not in payload["message"]
