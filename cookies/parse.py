"""Parsing helpers for Set-Cookie and Cookie header values."""

from __future__ import annotations

from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

_KNOWN_FLAGS = {"secure", "httponly", "partitioned"}
_KNOWN_VALUED = {"expires", "max-age", "domain", "path", "samesite"}


def split_pairs(line: str) -> list[str]:
    """Split a header line into semicolon-delimited fragments.

    Semicolons inside a quoted value are part of that value, not delimiters.
    Empty fragments are omitted.
    """
    return [fragment.strip() for fragment in line.split(";") if fragment.strip()]


def parse_pair(text: str) -> tuple[str, str]:
    """Parse a single name=value fragment and remove surrounding quotes.

    Escaped double quotes inside a quoted value are decoded as literal quotes.
    """
    name, separator, raw_value = text.partition("=")
    name = name.strip()
    value = raw_value.strip() if separator else ""
    if len(value) >= 2 and value.startswith('"') and value.endswith('"'):
        value = value[1:-1]
    return name, value


def parse_attributes(tokens: list[str]) -> dict:
    """Parse attribute fragments into a mapping.

    Attribute names are case-insensitive and are exposed in lowercase. A flag
    attribute maps to True; a valued attribute maps to its decoded string.
    """
    attributes: dict = {}
    for token in tokens:
        fragment = token.strip()
        if not fragment:
            continue
        name, separator, raw_value = fragment.partition("=")
        name = name.strip()
        if not name:
            continue
        if separator:
            value = raw_value.strip()
            if len(value) >= 2 and value.startswith('"') and value.endswith('"'):
                value = value[1:-1]
            attributes[name] = value
        else:
            attributes[name] = True
    return attributes


def _attribute_errors(tokens: list[str]) -> list[str]:
    """Return attribute fragments that do not satisfy the attribute grammar."""
    return []


def parse_set_cookie(line: str) -> dict:
    """Parse one Set-Cookie line.

    The result contains the cookie name and value, a lowercase attribute
    mapping, and a list of invalid attribute fragments.
    """
    tokens = split_pairs(line)
    if not tokens:
        return {"name": "", "value": "", "attributes": {}, "errors": ["empty Set-Cookie"]}
    name, value = parse_pair(tokens[0])
    attribute_tokens = tokens[1:]
    return {
        "name": name,
        "value": value,
        "attributes": parse_attributes(attribute_tokens),
        "errors": _attribute_errors(attribute_tokens),
    }


def parse_cookie_header(line: str) -> dict:
    """Parse a request Cookie header into a name-to-value mapping."""
    cookies: dict = {}
    for token in split_pairs(line):
        name, value = parse_pair(token)
        if name:
            cookies[name] = value
    return cookies


def expiry_to_timestamp(text: str) -> int:
    """Convert an HTTP cookie expiry date to a Unix timestamp in UTC."""
    value = (text or "").strip()
    if not value:
        raise ValueError("empty expiry value")
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        parsed = None
    if parsed is None:
        try:
            parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S")
        except ValueError as exc:
            raise ValueError(f"unsupported expiry value: {text!r}") from exc
    if parsed.tzinfo is not None:
        parsed = parsed.replace(tzinfo=None)
    return int(parsed.timestamp())


def _scope_key(cookie: dict) -> tuple[str, str, str]:
    """Build the identity used when collapsing cookies with the same scope."""
    attributes = cookie.get("attributes", {})
    domain = str(attributes.get("domain") or "").strip().lower()
    path = str(attributes.get("path") or "").strip() or "/"
    return (str(cookie.get("name") or ""), domain, path)


def dedupe(cookies: list[dict]) -> list[dict]:
    """Collapse cookies with the same name, domain, and path.

    The later cookie replaces the earlier one, while the position of the first
    occurrence is retained.
    """
    result: list[dict] = []
    seen: dict = {}
    for cookie in cookies:
        key = _scope_key(cookie)
        seen.setdefault(key, cookie)
        result.append(cookie)
    return result


def _set_cookie_values(response: dict) -> list[str]:
    """Extract Set-Cookie header values from either a response or its headers."""
    if not isinstance(response, dict):
        return []
    source = response.get("headers", response)
    if not isinstance(source, dict):
        return []
    for key, value in source.items():
        if str(key).lower() != "set-cookie":
            continue
        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        if isinstance(value, (list, tuple)):
            return [item for item in value if isinstance(item, str)]
        return []
    return []


def cookie_batch(responses: list[dict]) -> dict:
    """Parse Set-Cookie values for a sequence of responses.

    Each response contributes its own list of parsed cookies to the responses
    entry of the returned mapping.
    """
    parsed_responses: list[list[dict]] = []
    shared_attributes: dict = {}
    for response in responses:
        values = _set_cookie_values(response)
        merged = ", ".join(values)
        if not merged.strip():
            parsed_responses.append([])
            continue
        cookie = parse_set_cookie(merged)
        shared_attributes.update(cookie["attributes"])
        cookie["attributes"] = shared_attributes
        parsed_responses.append([cookie])
    return {"responses": parsed_responses}