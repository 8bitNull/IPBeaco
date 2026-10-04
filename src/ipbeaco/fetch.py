"""Download a single feed using a caller-owned HTTP client."""

import re
import time

import httpx

from ipbeaco.models import Settings, SourceError


def download(url: str, settings: Settings, client: httpx.Client) -> bytes:
    """Fetch decoded bytes with bounded attempts and a decoded response size cap.

    The caller owns the client and its TLS verification policy. Redirects are
    disabled per request, regardless of client defaults. Only safe error codes
    and HTTP status numbers escape this boundary.
    """
    try:
        parsed = httpx.URL(url)
    except httpx.InvalidURL:
        raise SourceError("invalid_url") from None
    if parsed.scheme != "https" or not parsed.host or parsed.username or parsed.password:
        raise SourceError("invalid_url")

    for attempt in range(settings.attempts):
        try:
            with client.stream(
                "GET", parsed, follow_redirects=False, timeout=settings.timeout_seconds
            ) as response:
                status = response.status_code
                if not 200 <= status < 300:
                    error = f"http_status:{status}"
                    if status != 429 and not 500 <= status < 600:
                        raise SourceError(error)
                else:
                    content_type = response.headers.get("content-type", "").split(";", 1)[0]
                    if content_type.strip().lower() in {"text/html", "application/xhtml+xml"}:
                        raise SourceError("unexpected_html")
                    parts, size = [], 0
                    for chunk in response.iter_bytes():
                        size += len(chunk)
                        if size > settings.max_bytes:
                            raise SourceError("response_too_large")
                        parts.append(chunk)
                    body = b"".join(parts)
                    prefix = body.lstrip().removeprefix(b"\xef\xbb\xbf").lstrip()
                    if re.match(rb"(?i)(?:<!doctype\s+html\b|<html(?:\s|>))", prefix):
                        raise SourceError("unexpected_html")
                    return body
        except httpx.TimeoutException:
            error = "request_timeout"
        except (httpx.DecodingError, httpx.ProtocolError):
            raise SourceError("invalid_response") from None
        except httpx.RequestError:
            raise SourceError("request_failed") from None

        if attempt + 1 == settings.attempts:
            raise SourceError(error) from None
        time.sleep(attempt + 1)

    raise SourceError("invalid_settings")
