"""Parsing helpers for Set-Cookie and Cookie header values."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

_KNOWN_FLAGS = {"secure", "httponly", "partitioned"}
_KNOWN_VALUED = {"expires", "max-age", "domain", "path", "samesite"}

# RFC 6265 token characters: visible ASCII minus separators.
_TOKEN_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_MAX_AGE_RE = re.compile(r"^-?[0-9]+$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_SAMESITE_VALUES = {"strict", "lax", "none"}


def _is_token(text: str) -> bool:
    return bool(_TOKEN_RE.match(text))


def _unescape(text: str) -> str:
    """Decode backslash escapes inside a quoted value.

    ``\\"`` becomes a literal quote and ``\\\\`` becomes a literal backslash.
    Any other backslash sequence is preserved verbatim.
    """
    result: list[str] = []
    index = 0
    while index < len(text):
        char = text[index]
        if char == "\\" and index + 1 < len(text):
            following = text[index + 1]
            if following in ('"', "\\"):
                result.append(following)
                index += 2
                continue
        result.append(char)
        index += 1
    return "".join(result)


def _quoted_body(raw: str) -> str | None:
    """Return the decoded body of a fully quoted value, or None if malformed.

    A value is only considered quoted when it begins with a double quote and
    the matching closing quote is the last non-whitespace character.
    """
    if not raw.startswith('"'):
        return None
    body: list[str] = []
    escaped = False
    for index in range(1, len(raw)):
        char = raw[index]
        if escaped:
            body.append("\\")
            body.append(char)
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == '"':
            if raw[index + 1 :].strip():
                return None
            return _unescape("".join(body))
        body.append(char)
    return None


def _decode_value(raw: str) -> str | None:
    """Decode an attribute or cookie value, returning None when malformed."""
    if raw.startswith('"'):
        return _quoted_body(raw)
    if '"' in raw:
        return None
    if _CONTROL_RE.search(raw):
        return None
    return raw


def split_pairs(line: str) -> list[str]:
    """Split a header line into semicolon-delimited fragments.

    Semicolons inside a quoted value are part of that value, not delimiters.
    Backslash-escaped quotes do not terminate the quoted region. Empty
    fragments are omitted.
    """
    fragments: list[str] = []
    current: list[str] = []
    in_quotes = False
    escaped = False
    for char in line:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if in_quotes and char == "\\":
            current.append(char)
            escaped = True
            continue
        if char == '"':
            in_quotes = not in_quotes
            current.append(char)
            continue
        if char == ";" and not in_quotes:
            fragment = "".join(current).strip()
            if fragment:
                fragments.append(fragment)
            current = []
            continue
        current.append(char)
    fragment = "".join(current).strip()
    if fragment:
        fragments.append(fragment)
    return fragments


def parse_pair(text: str) -> tuple[str, str]:
    """Parse a single name=value fragment and remove surrounding quotes.

    Escaped double quotes inside a quoted value are decoded as literal quotes.
    """
    name, separator, raw_value = text.partition("=")
    name = name.strip()
    value = raw_value.strip() if separator else ""
    if len(value) >= 2 and value.startswith('"') and value.endswith('"'):
        decoded = _quoted_body(value)
        if decoded is not None:
            value = decoded
    return name, value


def _parse_attribute(
    fragment: str,
) -> tuple[str | None, object, bool]:
    """Parse one attribute fragment.

    Returns ``(name, value, invalid)``. ``name`` is lowercase; a flag maps to
    True. ``invalid`` marks fragments that violate the attribute grammar or a
    known attribute's value rules.
    """
    name, separator, raw_value = fragment.partition("=")
    name = name.strip()
    if not name or not _is_token(name):
        return None, None, True
    lowered = name.lower()

    if not separator:
        if lowered in _KNOWN_FLAGS:
            return lowered, True, False
        # A bare token is only meaningful for the well-known flag attributes.
        return None, None, True

    value = _decode_value(raw_value.strip())
    if value is None:
        return None, None, True

    if lowered == "max-age":
        if not _MAX_AGE_RE.match(value.strip()):
            return lowered, value, True
    elif lowered == "expires":
        try:
            expiry_to_timestamp(value)
        except ValueError:
            return lowered, value, True
    elif lowered == "samesite":
        if value.strip().lower() not in _SAMESITE_VALUES:
            return lowered, value, True
    elif lowered in ("domain", "path"):
        if not value.strip():
            return lowered, value, True
    return lowered, value, False


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
        name, value, invalid = _parse_attribute(fragment)
        if invalid or name is None:
            continue
        attributes[name] = value
    return attributes


def _attribute_errors(tokens: list[str]) -> list[str]:
    """Return attribute fragments that do not satisfy the attribute grammar.

    The list is sorted so that the order of the attributes in the header can
    never influence the parse result.
    """
    errors: list[str] = []
    for token in tokens:
        fragment = token.strip()
        if not fragment:
            continue
        _, _, invalid = _parse_attribute(fragment)
        if invalid:
            errors.append(fragment)
    return sorted(errors)


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
        candidate = value
        if candidate.endswith(("Z", "z")):
            candidate = candidate[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(candidate)
        except ValueError as exc:
            raise ValueError(f"unsupported expiry value: {text!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return int(parsed.astimezone(timezone.utc).timestamp())


def _normalize_domain(value: object) -> str:
    """Normalize a domain the way cookie scope matching expects it."""
    if not isinstance(value, str):
        return ""
    return value.strip().lstrip(".").lower()


def _normalize_path(value: object) -> str:
    """Normalize a path with the same leading-dot rule used for domains."""
    if not isinstance(value, str):
        return "/"
    normalized = value.strip().lstrip(".")
    return normalized or "/"


def _scope_key(cookie: dict) -> tuple[str, str, str]:
    """Build the identity used when collapsing cookies with the same scope."""
    attributes = cookie.get("attributes", {})
    if not isinstance(attributes, dict):
        attributes = {}
    domain = _normalize_domain(attributes.get("domain"))
    path = _normalize_path(attributes.get("path"))
    return (str(cookie.get("name") or ""), domain, path)


def dedupe(cookies: list[dict]) -> list[dict]:
    """Collapse cookies with the same name, domain, and path.

    The later cookie replaces the earlier one, while the position of the first
    occurrence is retained. Domains and paths are compared after normalizing
    leading dots (and lowercasing domains), so a dotted and undotted value are
    treated as the same scope.
    """
    result: list[dict] = []
    positions: dict = {}
    for cookie in cookies:
        key = _scope_key(cookie)
        if key in positions:
            result[positions[key]] = cookie
        else:
            positions[key] = len(result)
            result.append(cookie)
    return result


def _set_cookie_values(response: dict) -> list[str]:
    """Extract Set-Cookie header values from either a response or its headers.

    Every Set-Cookie entry is preserved individually; headers are matched
    case-insensitively and may be a mapping or a sequence of name/value pairs.
    """
    if not isinstance(response, dict):
        return []
    source = response.get("headers", response)
    if source is response and not _has_header_container(response):
        return []

    values: list[str] = []
    if isinstance(source, dict):
        for key, value in source.items():
            if str(key).lower() != "set-cookie":
                continue
            values.extend(_string_values(value))
    elif isinstance(source, (list, tuple)):
        for item in source:
            if not isinstance(item, (list, tuple)) or len(item) != 2:
                continue
            key, value = item
            if str(key).lower() != "set-cookie":
                continue
            values.extend(_string_values(value))
    return values


def _has_header_container(response: dict) -> bool:
    return any(str(key).lower() == "set-cookie" for key in response)


def _string_values(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return [item for item in value if isinstance(item, str)]
    return []


def cookie_batch(responses: list[dict]) -> dict:
    """Parse Set-Cookie values for a sequence of responses.

    Each Set-Cookie value is parsed as its own cookie and each response is
    handled independently: nothing (attributes included) is shared between
    responses or between cookies.
    """
    parsed_responses: list[list[dict]] = []
    for response in responses or []:
        cookies = [
            parse_set_cookie(value)
            for value in _set_cookie_values(response)
            if value.strip()
        ]
        parsed_responses.append(cookies)
    return {"responses": parsed_responses}
