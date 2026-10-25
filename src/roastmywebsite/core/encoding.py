from __future__ import annotations

import random
import urllib.parse


def encode_none(payload: str) -> str:
    return payload


def encode_url(payload: str) -> str:
    return urllib.parse.quote(payload, safe="")


def encode_double_url(payload: str) -> str:
    return urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")


def encode_case(payload: str) -> str:
    """Randomize case of alphabetic characters."""
    result = []
    for ch in payload:
        if ch.isalpha() and random.random() < 0.5:
            result.append(ch.swapcase())
        else:
            result.append(ch)
    return "".join(result)


def encode_comments(payload: str) -> str:
    """Insert SQL comments between keywords (SQL-specific)."""
    # Insert /**/ between spaces for SQL payloads
    return payload.replace(" ", "/**/")


def encode_unicode(payload: str) -> str:
    """Replace spaces with unicode non-breaking space or similar."""
    return payload.replace(" ", "\u00a0")


def encode_hex(payload: str) -> str:
    """Hex-encode the payload (for SQL: 0x...)."""
    return "0x" + payload.encode().hex()


ENCODERS = {
    "none": encode_none,
    "url": encode_url,
    "double_url": encode_double_url,
    "case": encode_case,
    "comments": encode_comments,
    "unicode": encode_unicode,
    "hex": encode_hex,
}


def encode_payload(payload: str, encoding: str) -> str:
    """Apply a single encoding to a payload."""
    encoder = ENCODERS.get(encoding.strip().lower())
    if encoder is None:
        return payload
    try:
        return encoder(payload)
    except Exception:
        return payload


def encode_payloads(payloads: list[str], encoding_str: str) -> list[str]:
    """Apply one or more encodings to a list of payloads.

    encoding_str: comma-separated list of encoding names, or "all".
    Returns deduplicated list of encoded payloads.
    """
    if not encoding_str or encoding_str.strip().lower() == "none":
        return list(payloads)

    if encoding_str.strip().lower() == "all":
        encodings = [e for e in ENCODERS if e != "none"]
    else:
        encodings = [e.strip().lower() for e in encoding_str.split(",") if e.strip()]

    result: list[str] = []
    seen: set[str] = set()
    for payload in payloads:
        for enc in encodings:
            encoded = encode_payload(payload, enc)
            if encoded not in seen:
                seen.add(encoded)
                result.append(encoded)
        # Always include original
        if payload not in seen:
            seen.add(payload)
            result.append(payload)

    return result


def fragment_payload(payload: str, num_fragments: int = 2) -> list[str]:
    """Split a payload into fragments for HTTP Parameter Pollution."""
    if num_fragments < 2 or len(payload) < num_fragments:
        return [payload]
    chunk_size = len(payload) // num_fragments
    fragments = []
    for i in range(num_fragments):
        start = i * chunk_size
        end = start + chunk_size if i < num_fragments - 1 else len(payload)
        fragments.append(payload[start:end])
    return fragments


def encode_tuple_payloads(
    payloads: list[tuple[str, ...]], encoding_str: str
) -> list[tuple[str, ...]]:
    """Apply encoding to tuple-based payloads (e.g. boolean pairs).

    Encodes each string element of each tuple.
    """
    if not encoding_str or encoding_str.strip().lower() == "none":
        return list(payloads)

    if encoding_str.strip().lower() == "all":
        encodings = [e for e in ENCODERS if e != "none"]
    else:
        encodings = [e.strip().lower() for e in encoding_str.split(",") if e.strip()]

    result: list[tuple[str, ...]] = []
    seen: set[tuple[str, ...]] = set()
    for item in payloads:
        for enc in encodings:
            encoded = tuple(encode_payload(str(elem), enc) for elem in item)
            if encoded not in seen:
                seen.add(encoded)
                result.append(encoded)
        if item not in seen:
            seen.add(item)
            result.append(item)

    return result