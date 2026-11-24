"""SSL/TLS certificate inspection, expiration monitoring, and security protocol auditing."""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass, field
import datetime
import math
import socket
import ssl
from typing import Any
from urllib.parse import urlparse


@dataclass
class SslConfig:
    """Configuration for SSL/TLS certificate inspection."""

    enabled: bool = False
    expiry_warning_days: int | None = None
    require_tls_version: str | None = None
    timeout: float = 10.0


@dataclass
class SslCertificateInfo:
    """Metadata and validation outcome for an SSL/TLS certificate."""

    is_https: bool = False
    valid: bool | None = None
    status: str = "none"  # "valid", "warning", "expired", "error", "not_https", "none"
    expires_at: str | None = None  # ISO-8601 formatted string UTC
    days_remaining: int | None = None
    issued_at: str | None = None  # ISO-8601 formatted string UTC
    issuer_cn: str | None = None
    issuer_org: str | None = None
    subject_cn: str | None = None
    sans: list[str] = field(default_factory=list)
    tls_version: str | None = None
    cipher_suite: str | None = None
    error: str | None = None
    warning: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> SslCertificateInfo | None:
        if not data or not isinstance(data, dict):
            return None
        return cls(
            is_https=bool(data.get("is_https", False)),
            valid=data.get("valid"),
            status=str(data.get("status", "none")),
            expires_at=data.get("expires_at"),
            days_remaining=data.get("days_remaining"),
            issued_at=data.get("issued_at"),
            issuer_cn=data.get("issuer_cn"),
            issuer_org=data.get("issuer_org"),
            subject_cn=data.get("subject_cn"),
            sans=list(data.get("sans", [])),
            tls_version=data.get("tls_version"),
            cipher_suite=data.get("cipher_suite"),
            error=data.get("error"),
            warning=data.get("warning"),
        )


def _extract_rdn_field(components: tuple[Any, ...], field_name: str) -> str | None:
    """Extract a relative distinguished name field (e.g. 'commonName' or 'organizationName')."""
    for rdn in components:
        for item in rdn:
            if isinstance(item, (tuple, list)) and len(item) == 2:
                key, val = item
                if key == field_name:
                    return str(val)
    return None


def parse_tls_version_number(version_str: str) -> tuple[int, ...]:
    """Normalize and parse a TLS version string (e.g. 'TLSv1.3', '1.3', 'TLS1.2') into a tuple."""
    cleaned = (
        version_str.replace("TLSv", "")
        .replace("TLS", "")
        .replace("v", "")
        .strip()
    )
    parts = []
    for part in cleaned.split("."):
        try:
            parts.append(int(part))
        except ValueError:
            parts.append(0)
    return tuple(parts)


def compare_tls_version(negotiated: str, required: str) -> bool:
    """Return True if the negotiated TLS version satisfies the required minimum version."""
    neg_tuple = parse_tls_version_number(negotiated)
    req_tuple = parse_tls_version_number(required)
    return neg_tuple >= req_tuple


async def _open_ssl_connection(
    hostname: str,
    port: int,
    ctx: ssl.SSLContext,
    timeout: float,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Connect to host and perform SSL/TLS handshake with dual-stack Happy Eyeballs.

    Supports IPv6 and IPv4 with RFC 8305 Happy Eyeballs (interleaving address families
    and falling back to IPv4 if IPv6 routing stalls or drops packets). Also provides
    explicit IPv4 fallback if the dual-stack attempt encounters network timeouts or
    unreachable IPv6 routes.
    """
    is_ipv6_literal = ":" in hostname

    try:
        return await asyncio.wait_for(
            asyncio.open_connection(
                hostname,
                port,
                ssl=ctx,
                server_hostname=hostname,
                happy_eyeballs_delay=0.25,
            ),
            timeout=timeout,
        )
    except TypeError:
        # Fallback if custom mock or older loop does not accept happy_eyeballs_delay kwarg
        try:
            return await asyncio.wait_for(
                asyncio.open_connection(
                    hostname,
                    port,
                    ssl=ctx,
                    server_hostname=hostname,
                ),
                timeout=timeout,
            )
        except (asyncio.TimeoutError, OSError) as exc:
            if not is_ipv6_literal:
                return await asyncio.wait_for(
                    asyncio.open_connection(
                        hostname,
                        port,
                        ssl=ctx,
                        server_hostname=hostname,
                        family=socket.AF_INET,
                    ),
                    timeout=timeout,
                )
            raise exc
    except (asyncio.TimeoutError, OSError) as exc:
        if not is_ipv6_literal:
            try:
                return await asyncio.wait_for(
                    asyncio.open_connection(
                        hostname,
                        port,
                        ssl=ctx,
                        server_hostname=hostname,
                        family=socket.AF_INET,
                    ),
                    timeout=min(timeout, 5.0),
                )
            except Exception:
                raise exc
        raise exc


async def inspect_ssl_certificate(
    url: str,
    ssl_config: SslConfig | None = None,
    now: datetime.datetime | None = None,
) -> SslCertificateInfo:
    """Asynchronously inspect the SSL/TLS certificate of a target URL."""
    config = ssl_config or SslConfig(enabled=True)
    if now is None:
        now = datetime.datetime.now(datetime.timezone.utc)

    parsed = urlparse(url)
    scheme = parsed.scheme.lower() if parsed.scheme else ""

    if scheme != "https":
        return SslCertificateInfo(
            is_https=False,
            valid=None,
            status="not_https",
        )

    hostname = parsed.hostname
    if not hostname:
        return SslCertificateInfo(
            is_https=True,
            valid=False,
            status="error",
            error="Missing hostname in HTTPS URL",
        )

    port = parsed.port if parsed.port is not None else 443

    # Attempt 1: Strict default validation
    try:
        ctx = ssl.create_default_context()
        reader, writer = await _open_ssl_connection(
            hostname,
            port,
            ctx,
            config.timeout,
        )

        ssl_obj = writer.get_extra_info("ssl_object")
        cert: dict[str, Any] = ssl_obj.getpeercert() or {}
        negotiated_tls = ssl_obj.version()
        cipher_tuple = ssl_obj.cipher()
        cipher_name = cipher_tuple[0] if cipher_tuple else None

        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

        # Extract dates
        expires_at_iso = None
        issued_at_iso = None
        days_remaining = None
        is_expired = False

        if "notAfter" in cert:
            try:
                not_after_epoch = ssl.cert_time_to_seconds(cert["notAfter"])
                exp_dt = datetime.datetime.fromtimestamp(not_after_epoch, tz=datetime.timezone.utc)
                expires_at_iso = exp_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
                delta_seconds = (exp_dt - now).total_seconds()
                days_remaining = int(math.floor(delta_seconds / 86400.0))
                if days_remaining < 0:
                    is_expired = True
            except Exception:
                pass

        if "notBefore" in cert:
            try:
                not_before_epoch = ssl.cert_time_to_seconds(cert["notBefore"])
                issued_dt = datetime.datetime.fromtimestamp(not_before_epoch, tz=datetime.timezone.utc)
                issued_at_iso = issued_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
            except Exception:
                pass

        issuer_components = cert.get("issuer", ())
        issuer_cn = _extract_rdn_field(issuer_components, "commonName")
        issuer_org = _extract_rdn_field(issuer_components, "organizationName")

        subject_components = cert.get("subject", ())
        subject_cn = _extract_rdn_field(subject_components, "commonName")

        sans = [
            val
            for kind, val in cert.get("subjectAltName", ())
            if kind == "DNS" or kind == "IP Address"
        ]

        # Evaluate TLS version requirement
        if config.require_tls_version and negotiated_tls:
            if not compare_tls_version(negotiated_tls, config.require_tls_version):
                return SslCertificateInfo(
                    is_https=True,
                    valid=False,
                    status="error",
                    expires_at=expires_at_iso,
                    days_remaining=days_remaining,
                    issued_at=issued_at_iso,
                    issuer_cn=issuer_cn,
                    issuer_org=issuer_org,
                    subject_cn=subject_cn,
                    sans=sans,
                    tls_version=negotiated_tls,
                    cipher_suite=cipher_name,
                    error=(
                        f"Negotiated TLS version {negotiated_tls} does not meet required "
                        f"{config.require_tls_version}"
                    ),
                )

        if is_expired:
            return SslCertificateInfo(
                is_https=True,
                valid=False,
                status="expired",
                expires_at=expires_at_iso,
                days_remaining=days_remaining,
                issued_at=issued_at_iso,
                issuer_cn=issuer_cn,
                issuer_org=issuer_org,
                subject_cn=subject_cn,
                sans=sans,
                tls_version=negotiated_tls,
                cipher_suite=cipher_name,
                error=f"Certificate expired {abs(days_remaining or 0)} days ago",
            )

        if (
            config.expiry_warning_days is not None
            and days_remaining is not None
            and days_remaining <= config.expiry_warning_days
        ):
            return SslCertificateInfo(
                is_https=True,
                valid=True,
                status="warning",
                expires_at=expires_at_iso,
                days_remaining=days_remaining,
                issued_at=issued_at_iso,
                issuer_cn=issuer_cn,
                issuer_org=issuer_org,
                subject_cn=subject_cn,
                sans=sans,
                tls_version=negotiated_tls,
                cipher_suite=cipher_name,
                warning=(
                    f"Certificate expires in {days_remaining} days "
                    f"(warning threshold: {config.expiry_warning_days}d)"
                ),
            )

        return SslCertificateInfo(
            is_https=True,
            valid=True,
            status="valid",
            expires_at=expires_at_iso,
            days_remaining=days_remaining,
            issued_at=issued_at_iso,
            issuer_cn=issuer_cn,
            issuer_org=issuer_org,
            subject_cn=subject_cn,
            sans=sans,
            tls_version=negotiated_tls,
            cipher_suite=cipher_name,
        )

    except ssl.SSLCertVerificationError as exc:
        err_msg = exc.verify_message or str(exc)
        is_expired = "expired" in err_msg.lower() or "notafter" in err_msg.lower()
        return SslCertificateInfo(
            is_https=True,
            valid=False,
            status="expired" if is_expired else "error",
            error=f"Certificate verification failed: {err_msg}",
        )
    except ssl.SSLError as exc:
        return SslCertificateInfo(
            is_https=True,
            valid=False,
            status="error",
            error=f"SSL handshake error: {exc}",
        )
    except asyncio.TimeoutError:
        return SslCertificateInfo(
            is_https=True,
            valid=False,
            status="error",
            error=f"SSL connection timed out after {config.timeout}s",
        )
    except (OSError, Exception) as exc:
        return SslCertificateInfo(
            is_https=True,
            valid=False,
            status="error",
            error=f"Connection failed: {exc}",
        )
