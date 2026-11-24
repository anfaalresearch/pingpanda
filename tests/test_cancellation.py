"""Tests for graceful scan cancellation and checkpoint-safe shutdown."""

import httpx
import pytest

from pingpanda.cancellation import (
    CancellationToken,
    ScanCancelled,
    capture_sigint,
)
from pingpanda.checkpoint import load_checkpoint


async def test_check_all_stops_scheduling_after_cancellation(
    checker, mock_transport, fake_dns
):
    urls = [
        "https://first.test/",
        "https://second.test/",
        "https://third.test/",
    ]
    requested = []
    token = CancellationToken()

    def handler(request):
        requested.append(str(request.url))
        return httpx.Response(200)

    def cancel_after_first_result(completed):
        if len(completed) == 1:
            token.cancel()

    mock_transport(handler)

    with pytest.raises(ScanCancelled) as exc_info:
        await checker.check_all(
            urls,
            on_result=cancel_after_first_result,
            max_concurrent=1,
            cancellation_token=token,
        )

    assert requested == ["https://first.test/"]
    assert list(exc_info.value.results) == [0]


async def test_cancelled_scan_preserves_initial_results_without_new_requests(
    checker, mock_transport, make_result
):
    urls = ["https://done.test/", "https://pending.test/"]
    initial = {0: make_result(url=urls[0], url_id=0)}
    token = CancellationToken()
    token.cancel()

    def unexpected_request(request):
        raise AssertionError("No request should start after cancellation.")

    mock_transport(unexpected_request)

    with pytest.raises(ScanCancelled) as exc_info:
        await checker.check_all(
            urls,
            initial_results=initial,
            cancellation_token=token,
        )

    assert exc_info.value.results == initial


async def test_cli_cancelled_scan_saves_checkpoint_and_returns_130(
    checker, monkeypatch, make_result, tmp_path, capsys
):
    urls = ["https://done.test/", "https://pending.test/"]
    list_file = tmp_path / "urls.txt"
    list_file.write_text("\n".join(urls) + "\n", encoding="utf-8")
    checkpoint = tmp_path / "scan.json"
    completed = {0: make_result(url=urls[0], url_id=0, status=200)}

    async def cancelled_check_all(*args, **kwargs):
        raise ScanCancelled(completed)

    monkeypatch.setattr(checker.cli, "check_all", cancelled_check_all)

    exit_code = await checker.main(
        [
            "-l",
            str(list_file),
            "--checkpoint",
            str(checkpoint),
            "--quiet",
        ]
    )

    output = capsys.readouterr().out
    restored = load_checkpoint(checkpoint, urls)

    assert exit_code == 130
    assert list(restored) == [0]
    assert "Scan interrupted." in output
    assert "Completed: 1 / 2" in output
    assert "Pending: 1" in output
    assert f"Checkpoint saved to: {checkpoint}" in output
    assert "--resume" in output


def test_sigint_first_requests_cancellation_second_delegates(
    monkeypatch,
):
    import pingpanda.cancellation as cancellation

    token = CancellationToken()
    previous_calls = []
    installed_handlers = []

    def previous_handler(signum, frame):
        previous_calls.append((signum, frame))

    def fake_signal(signum, handler):
        installed_handlers.append((signum, handler))

    monkeypatch.setattr(
        cancellation.signal,
        "getsignal",
        lambda signum: previous_handler,
    )
    monkeypatch.setattr(cancellation.signal, "signal", fake_signal)

    with capture_sigint(token):
        handler = installed_handlers[0][1]

        handler(cancellation.signal.SIGINT, None)
        assert token.cancelled is True
        assert previous_calls == []

        handler(cancellation.signal.SIGINT, None)
        assert previous_calls == [(cancellation.signal.SIGINT, None)]

    assert installed_handlers[-1] == (
        cancellation.signal.SIGINT,
        previous_handler,
    )


def test_sigint_context_falls_back_when_handler_cannot_be_installed(
    monkeypatch,
):
    import pingpanda.cancellation as cancellation

    token = CancellationToken()

    monkeypatch.setattr(
        cancellation.signal,
        "getsignal",
        lambda signum: cancellation.signal.SIG_DFL,
    )

    def fail_to_install(signum, handler):
        raise ValueError("not in main thread")

    monkeypatch.setattr(cancellation.signal, "signal", fail_to_install)

    with capture_sigint(token) as active_token:
        assert active_token is token
        assert token.cancelled is False
