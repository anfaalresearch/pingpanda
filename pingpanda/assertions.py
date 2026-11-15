"""HTTP health assertions and response-time SLA evaluation engine."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Mapping


@dataclass
class AssertionConfig:
    """Configuration for HTTP assertions and custom request options."""

    expect_status: set[int] | None = None
    expect_body: str | None = None
    expect_body_regex: re.Pattern[str] | None = None
    expect_headers: dict[str, str | None] = field(default_factory=dict)
    max_latency: float | None = None
    custom_headers: dict[str, str] = field(default_factory=dict)

    @property
    def has_assertions(self) -> bool:
        """Whether any assertion rules are configured."""
        return (
            self.expect_status is not None
            or self.expect_body is not None
            or self.expect_body_regex is not None
            or bool(self.expect_headers)
            or self.max_latency is not None
        )

    @property
    def requires_body(self) -> bool:
        """Whether evaluating assertions requires reading the response body."""
        return self.expect_body is not None or self.expect_body_regex is not None


def parse_status_codes(spec: str) -> set[int]:
    """Parse comma-separated status codes or ranges (e.g. '200,204' or '200-299')."""
    if not isinstance(spec, str) or not spec.strip():
        raise ValueError("Status code specification cannot be empty")

    codes: set[int] = set()
    parts = [p.strip() for p in spec.split(",") if p.strip()]
    if not parts:
        raise ValueError("Status code specification cannot be empty")

    for part in parts:
        if "-" in part:
            pieces = part.split("-")
            if len(pieces) != 2:
                raise ValueError(f"Invalid status code range format: '{part}'")
            start_str, end_str = pieces
            try:
                start, end = int(start_str.strip()), int(end_str.strip())
            except ValueError as exc:
                raise ValueError(f"Status codes in range must be integers: '{part}'") from exc

            if start > end or start < 100 or end > 599:
                raise ValueError(
                    f"Invalid status code range: '{part}'. Values must be between 100 and 599."
                )
            codes.update(range(start, end + 1))
        else:
            try:
                code = int(part)
            except ValueError as exc:
                raise ValueError(f"Status code must be an integer: '{part}'") from exc

            if code < 100 or code > 599:
                raise ValueError(f"Status code must be between 100 and 599: {code}")
            codes.add(code)

    return codes


def parse_header_option(header_str: str) -> tuple[str, str]:
    """Parse 'Name: Value' into a (name, value) tuple with whitespace stripped."""
    if not isinstance(header_str, str) or ":" not in header_str:
        raise ValueError(
            f"Header must be in 'Name: Value' format (missing colon): '{header_str}'"
        )
    name, value = header_str.split(":", 1)
    name = name.strip()
    value = value.strip()
    if not name:
        raise ValueError("Header name cannot be empty")
    return name, value


def parse_expect_header_option(header_str: str) -> tuple[str, str | None]:
    """Parse 'Name: Value' or 'Name' into (name, expected_value_or_None)."""
    if not isinstance(header_str, str) or not header_str.strip():
        raise ValueError("Header specification cannot be empty")

    header_str = header_str.strip()
    if ":" in header_str:
        name, value = header_str.split(":", 1)
        name = name.strip()
        value = value.strip()
        if not name:
            raise ValueError("Header name cannot be empty")
        return name, value

    return header_str, None


def evaluate_assertions(
    status: int | None,
    headers: Mapping[str, str] | None,
    body: str | None,
    elapsed: float,
    config: AssertionConfig | None,
) -> tuple[bool | None, list[str], bool]:
    """Evaluate response against configured assertions.

    Returns:
        (assertions_passed, assertion_failures, sla_breached)
        - If config is None or has no assertions: (None, [], False)
        - Otherwise: (bool, list of error messages, bool)
    """
    if config is None or not config.has_assertions:
        return None, [], False

    failures: list[str] = []
    sla_breached = False

    # 1. Latency SLA check
    if config.max_latency is not None:
        if elapsed > config.max_latency:
            sla_breached = True
            failures.append(
                f"Latency SLA breached: {elapsed:.3f}s exceeds threshold of {config.max_latency:.3f}s"
            )

    # 2. Status code check
    if status is None:
        failures.append("No HTTP response received (connection or network error)")
    elif config.expect_status is not None:
        if status not in config.expect_status:
            expected_sorted = ",".join(map(str, sorted(config.expect_status)))
            failures.append(
                f"Status code {status} not in expected set ({expected_sorted})"
            )

    # 3. Response body checks (only evaluated if response was received)
    if status is not None:
        safe_body = body or ""
        if config.expect_body is not None:
            if config.expect_body not in safe_body:
                failures.append(f"Response body missing expected text: '{config.expect_body}'")

        if config.expect_body_regex is not None:
            if not config.expect_body_regex.search(safe_body):
                failures.append(
                    f"Response body does not match regex: '{config.expect_body_regex.pattern}'"
                )

    # 4. Response header checks (case-insensitive header lookup)
    if config.expect_headers:
        if headers is None:
            for req_name in config.expect_headers:
                failures.append(f"Missing expected response header: '{req_name}'")
        else:
            normalized_headers = {k.lower(): v for k, v in headers.items()}
            for req_name, req_val in config.expect_headers.items():
                req_name_lower = req_name.lower()
                if req_name_lower not in normalized_headers:
                    failures.append(f"Missing expected response header: '{req_name}'")
                elif req_val is not None:
                    actual_val = normalized_headers[req_name_lower]
                    if actual_val.strip() != req_val.strip():
                        failures.append(
                            f"Header '{req_name}' value mismatch: expected '{req_val}', got '{actual_val}'"
                        )

    assertions_passed = len(failures) == 0
    return assertions_passed, failures, sla_breached
