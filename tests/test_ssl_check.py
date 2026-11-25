"""Tests for SSL/TLS certificate inspection, expiration tracking, and reporting."""

import asyncio
import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pingpanda.cli import build_ssl_config, parse_arguments
from pingpanda.models import UrlResult
from pingpanda.checkpoint import load_checkpoint, save_checkpoint
from pingpanda.report import (
    extract_scan_metrics,
    format_result_line,
    generate_csv_report,
    generate_json_report,
    generate_markdown_report,
    generate_text_report,
)
from pingpanda.ssl_check import (
    SslCertificateInfo,
    SslConfig,
    _extract_rdn_field,
    compare_tls_version,
    inspect_ssl_certificate,
    parse_tls_version_number,
)


def test_parse_tls_version_number():
    assert parse_tls_version_number("TLSv1.3") == (1, 3)
    assert parse_tls_version_number("1.2") == (1, 2)
    assert parse_tls_version_number("TLS1.1") == (1, 1)
    assert parse_tls_version_number("v2.0.1") == (2, 0, 1)
    assert parse_tls_version_number("invalid") == (0,)


def test_compare_tls_version():
    assert compare_tls_version("TLSv1.3", "1.2") is True
    assert compare_tls_version("TLSv1.2", "1.2") is True
    assert compare_tls_version("TLSv1.1", "1.2") is False
    assert compare_tls_version("TLSv1.0", "1.3") is False
    assert compare_tls_version("1.3", "TLSv1.3") is True


def test_extract_rdn_field():
    rdn = (
        (("countryName", "US"),),
        (("organizationName", "Example CA Ltd"), ("commonName", "Example Root CA")),
    )
    assert _extract_rdn_field(rdn, "commonName") == "Example Root CA"
    assert _extract_rdn_field(rdn, "organizationName") == "Example CA Ltd"
    assert _extract_rdn_field(rdn, "localityName") is None
    assert _extract_rdn_field((), "commonName") is None


def test_ssl_certificate_info_to_and_from_dict():
    info = SslCertificateInfo(
        is_https=True,
        valid=True,
        status="valid",
        expires_at="2027-01-01T00:00:00Z",
        days_remaining=250,
        issued_at="2026-01-01T00:00:00Z",
        issuer_cn="DigiCert Global Root",
        issuer_org="DigiCert Inc",
        subject_cn="example.com",
        sans=["example.com", "www.example.com"],
        tls_version="TLSv1.3",
        cipher_suite="TLS_AES_256_GCM_SHA384",
    )
    data = info.to_dict()
    assert data["status"] == "valid"
    assert data["days_remaining"] == 250
    assert data["sans"] == ["example.com", "www.example.com"]

    reconstructed = SslCertificateInfo.from_dict(data)
    assert reconstructed is not None
    assert reconstructed.is_https is True
    assert reconstructed.valid is True
    assert reconstructed.status == "valid"
    assert reconstructed.issuer_org == "DigiCert Inc"
    assert reconstructed.days_remaining == 250

    assert SslCertificateInfo.from_dict(None) is None
    assert SslCertificateInfo.from_dict({}) is None


@pytest.mark.asyncio
async def test_inspect_ssl_non_https():
    res = await inspect_ssl_certificate("http://example.com/test")
    assert res.is_https is False
    assert res.valid is None
    assert res.status == "not_https"


@pytest.mark.asyncio
async def test_inspect_ssl_missing_hostname():
    res = await inspect_ssl_certificate("https:///path")
    assert res.is_https is True
    assert res.valid is False
    assert res.status == "error"
    assert "Missing hostname" in (res.error or "")


@pytest.mark.asyncio
async def test_inspect_ssl_valid_mocked():
    mock_writer = MagicMock()
    mock_ssl_obj = MagicMock()

    # Expires in ~100 days relative to 2026-11-20
    cert = {
        "notAfter": "Feb 28 00:00:00 2027 GMT",
        "notBefore": "Nov 01 00:00:00 2026 GMT",
        "issuer": ((("organizationName", "TrustCo"), ("commonName", "TrustCo CA")),),
        "subject": ((("commonName", "api.example.com"),),),
        "subjectAltName": (("DNS", "api.example.com"), ("DNS", "example.com")),
    }
    mock_ssl_obj.getpeercert.return_value = cert
    mock_ssl_obj.version.return_value = "TLSv1.3"
    mock_ssl_obj.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    mock_writer.get_extra_info.return_value = mock_ssl_obj
    mock_writer.wait_closed = AsyncMock()

    frozen_now = datetime.datetime(2026, 11, 20, 0, 0, 0, tzinfo=datetime.timezone.utc)

    with patch("asyncio.open_connection", new=AsyncMock(return_value=(MagicMock(), mock_writer))):
        res = await inspect_ssl_certificate("https://api.example.com", now=frozen_now)

    assert res.is_https is True
    assert res.valid is True
    assert res.status == "valid"
    assert res.issuer_org == "TrustCo"
    assert res.issuer_cn == "TrustCo CA"
    assert res.subject_cn == "api.example.com"
    assert "example.com" in res.sans
    assert res.tls_version == "TLSv1.3"
    assert res.days_remaining is not None
    assert res.days_remaining > 90


@pytest.mark.asyncio
async def test_inspect_ssl_expiry_warning_threshold():
    mock_writer = MagicMock()
    mock_ssl_obj = MagicMock()

    # Expires in 15 days relative to 2026-11-20
    cert = {
        "notAfter": "Dec 05 00:00:00 2026 GMT",
        "notBefore": "Oct 01 00:00:00 2026 GMT",
        "issuer": ((("organizationName", "FastCert Inc"),),),
        "subject": ((("commonName", "staging.example.com"),),),
    }
    mock_ssl_obj.getpeercert.return_value = cert
    mock_ssl_obj.version.return_value = "TLSv1.2"
    mock_ssl_obj.cipher.return_value = ("ECDHE-RSA-AES128-GCM-SHA256", "TLSv1.2", 128)
    mock_writer.get_extra_info.return_value = mock_ssl_obj
    mock_writer.wait_closed = AsyncMock()

    frozen_now = datetime.datetime(2026, 11, 20, 0, 0, 0, tzinfo=datetime.timezone.utc)
    config = SslConfig(enabled=True, expiry_warning_days=30)

    with patch("asyncio.open_connection", new=AsyncMock(return_value=(MagicMock(), mock_writer))):
        res = await inspect_ssl_certificate("https://staging.example.com", ssl_config=config, now=frozen_now)

    assert res.is_https is True
    assert res.valid is True
    assert res.status == "warning"
    assert res.days_remaining == 15
    assert "expires in 15 days" in (res.warning or "").lower()


@pytest.mark.asyncio
async def test_inspect_ssl_expired():
    mock_writer = MagicMock()
    mock_ssl_obj = MagicMock()

    # Expired 10 days ago relative to 2026-11-20
    cert = {
        "notAfter": "Nov 10 00:00:00 2026 GMT",
        "notBefore": "Nov 10 00:00:00 2025 GMT",
        "issuer": ((("commonName", "Expired CA"),),),
    }
    mock_ssl_obj.getpeercert.return_value = cert
    mock_ssl_obj.version.return_value = "TLSv1.3"
    mock_ssl_obj.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    mock_writer.get_extra_info.return_value = mock_ssl_obj
    mock_writer.wait_closed = AsyncMock()

    frozen_now = datetime.datetime(2026, 11, 20, 0, 0, 0, tzinfo=datetime.timezone.utc)

    with patch("asyncio.open_connection", new=AsyncMock(return_value=(MagicMock(), mock_writer))):
        res = await inspect_ssl_certificate("https://expired.example.com", now=frozen_now)

    assert res.is_https is True
    assert res.valid is False
    assert res.status == "expired"
    assert "expired" in (res.error or "").lower()


@pytest.mark.asyncio
async def test_inspect_ssl_require_tls_version():
    mock_writer = MagicMock()
    mock_ssl_obj = MagicMock()
    cert = {
        "notAfter": "Feb 28 00:00:00 2027 GMT",
        "notBefore": "Nov 01 00:00:00 2026 GMT",
    }
    mock_ssl_obj.getpeercert.return_value = cert
    mock_ssl_obj.version.return_value = "TLSv1.1"  # Obsolete version
    mock_ssl_obj.cipher.return_value = ("AES128-SHA", "TLSv1.1", 128)
    mock_writer.get_extra_info.return_value = mock_ssl_obj
    mock_writer.wait_closed = AsyncMock()

    frozen_now = datetime.datetime(2026, 11, 20, 0, 0, 0, tzinfo=datetime.timezone.utc)

    # Require minimum TLS 1.2
    config = SslConfig(enabled=True, require_tls_version="1.2")
    with patch("asyncio.open_connection", new=AsyncMock(return_value=(MagicMock(), mock_writer))):
        res = await inspect_ssl_certificate("https://legacy.example.com", ssl_config=config, now=frozen_now)

    assert res.is_https is True
    assert res.valid is False
    assert res.status == "error"
    assert "does not meet required 1.2" in (res.error or "")

    # Now simulate TLS 1.3 meeting requirement 1.2
    mock_ssl_obj.version.return_value = "TLSv1.3"
    with patch("asyncio.open_connection", new=AsyncMock(return_value=(MagicMock(), mock_writer))):
        res_pass = await inspect_ssl_certificate("https://modern.example.com", ssl_config=config, now=frozen_now)

    assert res_pass.is_https is True
    assert res_pass.valid is True
    assert res_pass.status == "valid"


@pytest.mark.asyncio
async def test_inspect_ssl_timeout_and_error():
    with patch("asyncio.open_connection", side_effect=asyncio.TimeoutError()):
        res = await inspect_ssl_certificate("https://timeout.example.com")
        assert res.valid is False
        assert res.status == "error"
        assert "timed out" in (res.error or "").lower()

    with patch("asyncio.open_connection", side_effect=ConnectionRefusedError("Connection refused")):
        res_refused = await inspect_ssl_certificate("https://refused.example.com")
        assert res_refused.valid is False
        assert res_refused.status == "error"


def test_cli_ssl_arguments_and_build_ssl_config():
    args_none = parse_arguments(["-d", "example.com"])
    assert build_ssl_config(args_none) is None

    args_ssl = parse_arguments(["-d", "example.com", "--check-ssl"])
    cfg = build_ssl_config(args_ssl)
    assert cfg is not None
    assert cfg.enabled is True
    assert cfg.expiry_warning_days is None
    assert cfg.require_tls_version is None

    args_full = parse_arguments([
        "-d", "example.com",
        "--check-ssl",
        "--ssl-expiry-warning", "45",
        "--require-tls-version", "1.3",
    ])
    cfg_full = build_ssl_config(args_full)
    assert cfg_full is not None
    assert cfg_full.enabled is True
    assert cfg_full.expiry_warning_days == 45
    assert cfg_full.require_tls_version == "1.3"


def test_reporting_with_ssl_json_csv_markdown_text():
    ssl_valid = SslCertificateInfo(
        is_https=True,
        valid=True,
        status="valid",
        expires_at="2027-01-01T00:00:00Z",
        days_remaining=250,
        issuer_org="Google Trust Services",
        tls_version="TLSv1.3",
    )
    ssl_warn = SslCertificateInfo(
        is_https=True,
        valid=True,
        status="warning",
        expires_at="2026-12-01T00:00:00Z",
        days_remaining=10,
        warning="Expires in 10 days",
        issuer_org="Let's Encrypt",
        tls_version="TLSv1.3",
    )
    ssl_expired = SslCertificateInfo(
        is_https=True,
        valid=False,
        status="expired",
        expires_at="2026-11-01T00:00:00Z",
        days_remaining=-19,
        error="Expired 19 days ago",
        issuer_cn="Expired CA",
        tls_version="TLSv1.2",
    )
    ssl_http = SslCertificateInfo(is_https=False, valid=None, status="not_https")

    results = {
        "2xx": [
            UrlResult(0, "https://secure.example.com", 200, 0.12, None, "1.1.1.1:443", None, ssl_info=ssl_valid),
            UrlResult(1, "https://staging.example.com", 200, 0.25, None, "1.1.1.2:443", None, ssl_info=ssl_warn),
        ],
        "4xx": [
            UrlResult(2, "https://expired.example.com", 404, 0.35, None, "1.1.1.3:443", None, ssl_info=ssl_expired),
        ],
        "3xx": [
            UrlResult(3, "http://plain.example.com", 301, 0.05, None, "1.1.1.4:80", None, ssl_info=ssl_http),
        ],
    }

    # Format result line
    line = format_result_line(results["2xx"][0])
    assert "[SSL: Valid (250d remaining, Google Trust Services)]" in line

    warn_line = format_result_line(results["2xx"][1])
    assert "[SSL: WARNING (Expires in 10 days)]" in warn_line

    exp_line = format_result_line(results["4xx"][0])
    assert "[SSL: EXPIRED (Expired 19 days ago)]" in exp_line

    http_line = format_result_line(results["3xx"][0])
    assert "[SSL: N/A (HTTP)]" in http_line

    # Metrics
    metrics = extract_scan_metrics(results)
    assert metrics["ssl_configured"] is True
    assert metrics["ssl_total_checked"] == 3
    assert metrics["ssl_valid_count"] == 1
    assert metrics["ssl_warning_count"] == 1
    assert metrics["ssl_expired_count"] == 1
    assert metrics["ssl_not_https_count"] == 1

    # JSON Report
    json_out = generate_json_report(results)
    assert '"ssl_summary"' in json_out
    assert '"https_checked": 3' in json_out
    assert '"valid_count": 1' in json_out
    assert '"Google Trust Services"' in json_out

    # CSV Report
    csv_out = generate_csv_report(results)
    assert "ssl_status,ssl_valid,ssl_days_remaining" in csv_out
    assert "Google Trust Services" in csv_out
    assert "not_https" in csv_out

    # Markdown Report
    md_out = generate_markdown_report(results)
    assert "SSL/TLS Certificates" in md_out
    assert "3 HTTPS checked" in md_out
    assert "Google Trust Services" in md_out

    # Text Report
    text_out = generate_text_report(results)
    assert "[SSL/TLS] 3 HTTPS checked: 1 valid, 1 warning, 1 expired, 0 error" in text_out


def test_checkpoint_persistence_with_ssl(tmp_path):
    checkpoint_file = tmp_path / ".checkpoint.json"
    urls = ["https://api.github.com", "http://plain.com"]

    ssl_info = SslCertificateInfo(
        is_https=True,
        valid=True,
        status="valid",
        expires_at="2027-01-01T00:00:00Z",
        days_remaining=240,
        issuer_org="DigiCert Inc",
        tls_version="TLSv1.3",
    )

    results = {
        0: UrlResult(0, "https://api.github.com", 200, 0.15, None, "140.82.112.4:443", None, ssl_info=ssl_info),
        1: UrlResult(1, "http://plain.com", 200, 0.08, None, "93.184.216.34:80", None),
    }

    save_checkpoint(checkpoint_file, urls, results)
    loaded = load_checkpoint(checkpoint_file, urls)

    assert len(loaded) == 2
    assert loaded[0].ssl_info is not None
    assert loaded[0].ssl_info.is_https is True
    assert loaded[0].ssl_info.issuer_org == "DigiCert Inc"
    assert loaded[0].ssl_info.days_remaining == 240
    assert loaded[1].ssl_info is None


@pytest.mark.asyncio
async def test_inspect_ssl_happy_eyeballs_invocation():
    mock_writer = MagicMock()
    mock_ssl_obj = MagicMock()
    mock_ssl_obj.getpeercert.return_value = {
        "notAfter": "Feb 28 00:00:00 2027 GMT",
        "issuer": ((("organizationName", "Trust"),),),
    }
    mock_ssl_obj.version.return_value = "TLSv1.3"
    mock_ssl_obj.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    mock_writer.get_extra_info.return_value = mock_ssl_obj
    mock_writer.wait_closed = AsyncMock()

    called_kwargs = {}

    async def mock_open_conn(host, port, **kwargs):
        nonlocal called_kwargs
        called_kwargs = kwargs
        return MagicMock(), mock_writer

    with patch("asyncio.open_connection", side_effect=mock_open_conn):
        res = await inspect_ssl_certificate("https://dualstack.example.com")

    assert res.valid is True
    assert called_kwargs.get("happy_eyeballs_delay") == 0.25
    assert called_kwargs.get("server_hostname") == "dualstack.example.com"


@pytest.mark.asyncio
async def test_inspect_ssl_fallback_to_ipv4_on_timeout():
    mock_writer = MagicMock()
    mock_ssl_obj = MagicMock()
    mock_ssl_obj.getpeercert.return_value = {
        "notAfter": "Feb 28 00:00:00 2027 GMT",
        "issuer": ((("organizationName", "Trust"),),),
    }
    mock_ssl_obj.version.return_value = "TLSv1.3"
    mock_ssl_obj.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    mock_writer.get_extra_info.return_value = mock_ssl_obj
    mock_writer.wait_closed = AsyncMock()

    call_history = []

    async def mock_open_conn(host, port, **kwargs):
        call_history.append(kwargs)
        if kwargs.get("family") == 2:  # socket.AF_INET
            return MagicMock(), mock_writer
        raise asyncio.TimeoutError()

    with patch("asyncio.open_connection", side_effect=mock_open_conn):
        res = await inspect_ssl_certificate("https://youtube.com")

    assert res.valid is True
    assert len(call_history) == 2
    assert call_history[0].get("happy_eyeballs_delay") == 0.25
    assert call_history[1].get("family") == 2


@pytest.mark.asyncio
async def test_inspect_ssl_type_error_compatibility_fallback():
    mock_writer = MagicMock()
    mock_ssl_obj = MagicMock()
    mock_ssl_obj.getpeercert.return_value = {
        "notAfter": "Feb 28 00:00:00 2027 GMT",
    }
    mock_ssl_obj.version.return_value = "TLSv1.3"
    mock_ssl_obj.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    mock_writer.get_extra_info.return_value = mock_ssl_obj
    mock_writer.wait_closed = AsyncMock()

    call_count = 0

    async def mock_open_conn(host, port, **kwargs):
        nonlocal call_count
        call_count += 1
        if "happy_eyeballs_delay" in kwargs:
            raise TypeError("unexpected keyword argument 'happy_eyeballs_delay'")
        return MagicMock(), mock_writer

    with patch("asyncio.open_connection", side_effect=mock_open_conn):
        res = await inspect_ssl_certificate("https://legacy-loop.example.com")

    assert res.valid is True
    assert call_count == 2

