"""Public acceptance tests."""

from cookies import (
    cookie_batch,
    expiry_to_timestamp,
    parse_cookie_header,
    parse_set_cookie,
)


def test_public_set_cookie_name_value():
    cookie = parse_set_cookie('session="abc;123"; Path=/; HttpOnly')
    assert cookie["name"] == "session"
    assert cookie["value"] == "abc;123"


def test_public_attribute_names_lowercase():
    cookie = parse_set_cookie(
        "sid=abc; pAtH=/app; SeCuRe; hTtPoNlY; sAmEsItE=LaX"
    )
    attributes = cookie["attributes"]
    assert attributes.get("path") == "/app"
    assert attributes.get("secure") is True
    assert attributes.get("httponly") is True
    assert "samesite" in attributes


def test_public_cookie_header():
    cookies = parse_cookie_header('a=1; b="x;y"; c=3')
    assert cookies == {"a": "1", "b": "x;y", "c": "3"}


def test_public_expiry_timestamp():
    assert expiry_to_timestamp("Wed, 21 Oct 2015 07:28:00 GMT") == 1445412480


def test_public_batch_isolation():
    batch = cookie_batch(
        [
            {"set-cookie": ["sid=1; Path=/; HttpOnly"]},
            {"set-cookie": ["theme=dark; Path=/; Secure"]},
        ]
    )
    first = batch["responses"][0][0]
    second = batch["responses"][1][0]
    assert first["attributes"].get("httponly") is True
    assert "httponly" not in second["attributes"]