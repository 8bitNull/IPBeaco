import gzip
import traceback

import httpx
import pytest

from ipbeaco.fetch import download
from ipbeaco.models import Settings, SourceError

URL = "https://example.invalid/list?token=secret"


class ChunkStream(httpx.SyncByteStream):
    def __init__(self, chunks):
        self.chunks = chunks
        self.read_count = 0
        self.closed = False

    def __iter__(self):
        for chunk in self.chunks:
            self.read_count += 1
            if isinstance(chunk, Exception):
                raise chunk
            yield chunk

    def close(self):
        self.closed = True


@pytest.fixture
def waits(monkeypatch):
    delays = []
    monkeypatch.setattr("ipbeaco.fetch.time.sleep", delays.append)
    return delays


def test_download_returns_bytes():
    with httpx.Client(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, content=b"1.2.3.4\n"))
    ) as client:
        assert download("https://example.invalid/list", Settings(), client) == b"1.2.3.4\n"


@pytest.mark.parametrize("status", [301, 302, 307, 308, 403, 404])
def test_permanent_http_error_is_not_retried_or_followed(status, waits):
    requests = []

    def respond(request):
        requests.append(request)
        return httpx.Response(status, headers={"location": "https://example.invalid/next"})

    with httpx.Client(transport=httpx.MockTransport(respond), follow_redirects=True) as client:
        with pytest.raises(SourceError, match=f"http_status:{status}$"):
            download(URL, Settings(), client)
    assert len(requests) == 1
    assert waits == []


@pytest.mark.parametrize("status", [429, 500, 502, 503, 599])
@pytest.mark.parametrize("attempts", [1, 2, 3])
def test_retryable_status_has_bounded_attempts(status, attempts, waits):
    requests = []

    def respond(request):
        requests.append(request)
        return httpx.Response(status, content=b"secret upstream body")

    with httpx.Client(transport=httpx.MockTransport(respond)) as client:
        with pytest.raises(SourceError, match=f"http_status:{status}$"):
            download(URL, Settings(attempts=attempts), client)
    assert len(requests) == attempts
    assert waits == list(range(1, attempts))


@pytest.mark.parametrize("error_type", [httpx.ConnectTimeout, httpx.ReadTimeout])
def test_timeout_retries_have_bounded_attempts(error_type, waits):
    requests = []

    def respond(request):
        requests.append(request)
        raise error_type("secret token in transport error", request=request)

    with httpx.Client(transport=httpx.MockTransport(respond)) as client:
        with pytest.raises(SourceError, match="request_timeout$") as caught:
            download(URL, Settings(attempts=3), client)
    assert len(requests) == 3
    assert waits == [1, 2]
    assert "secret" not in "".join(traceback.format_exception(caught.value))


def test_retry_success_discards_partial_response_and_closes_streams(waits):
    streams = [
        ChunkStream([b"partial", httpx.ReadTimeout("secret")]),
        ChunkStream([b"complete"]),
    ]
    requests = []

    def respond(request):
        requests.append(request)
        return httpx.Response(200, stream=streams[len(requests) - 1])

    with httpx.Client(transport=httpx.MockTransport(respond)) as client:
        assert download(URL, Settings(), client) == b"complete"
    assert len(requests) == 2
    assert waits == [1]
    assert all(stream.closed for stream in streams)


def test_retryable_status_then_success_returns_body(waits):
    statuses = iter([429, 503, 200])

    def respond(request):
        return httpx.Response(next(statuses), content=b"accepted")

    with httpx.Client(transport=httpx.MockTransport(respond)) as client:
        assert download(URL, Settings(), client) == b"accepted"
    assert waits == [1, 2]


def test_request_uses_settings_timeout(waits):
    def respond(request):
        assert request.extensions["timeout"] == {
            "connect": 7,
            "read": 7,
            "write": 7,
            "pool": 7,
        }
        return httpx.Response(200, content=b"ok")

    with httpx.Client(transport=httpx.MockTransport(respond), timeout=100) as client:
        assert download(URL, Settings(timeout_seconds=7), client) == b"ok"


def test_size_limit_stops_stream_and_closes_response(waits):
    stream = ChunkStream([b"123", b"45", b"never read"])
    with httpx.Client(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, stream=stream))
    ) as client:
        with pytest.raises(SourceError, match="response_too_large$"):
            download(URL, Settings(max_bytes=4), client)
    assert stream.read_count == 2
    assert stream.closed
    assert waits == []


@pytest.mark.parametrize("content", [b"", b"1234"])
def test_size_limit_allows_empty_and_exact_boundary(content):
    with httpx.Client(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, content=content))
    ) as client:
        assert download(URL, Settings(max_bytes=4), client) == content


def test_compressed_response_is_checked_after_decompression(waits):
    compressed = gzip.compress(b"1" * 1000)
    stream = ChunkStream([compressed])
    with httpx.Client(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                200,
                headers={"content-encoding": "gzip", "content-length": str(len(compressed))},
                stream=stream,
            )
        )
    ) as client:
        with pytest.raises(SourceError, match="response_too_large$"):
            download(URL, Settings(max_bytes=100), client)
    assert stream.closed
    assert waits == []


def test_valid_compressed_response_returns_decoded_bytes():
    stream = ChunkStream([gzip.compress(b"1.2.3.4\n")])
    with httpx.Client(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, headers={"content-encoding": "gzip"}, stream=stream)
        )
    ) as client:
        assert download(URL, Settings(max_bytes=8), client) == b"1.2.3.4\n"


def test_content_length_is_not_trusted_as_size_limit():
    with httpx.Client(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, headers={"content-length": "1"}, content=b"12345")
        )
    ) as client:
        with pytest.raises(SourceError, match="response_too_large$"):
            download(URL, Settings(max_bytes=4), client)


@pytest.mark.parametrize(
    "content_type", ["text/html; charset=UTF-8", "TEXT/HTML", "application/xhtml+xml"]
)
def test_html_content_type_is_rejected_before_reading(content_type, waits):
    stream = ChunkStream([b"secret"])
    with httpx.Client(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                200, headers={"content-type": content_type}, stream=stream
            )
        )
    ) as client:
        with pytest.raises(SourceError, match="unexpected_html$"):
            download(URL, Settings(), client)
    assert stream.read_count == 0
    assert stream.closed
    assert waits == []


@pytest.mark.parametrize(
    "chunks", [[b" <!DOC", b"TYPE html><body>secret"], [b"\xef\xbb\xbf\n<HTML>secret"]]
)
def test_html_document_start_is_rejected_without_html_content_type(chunks, waits):
    with httpx.Client(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, stream=ChunkStream(chunks))
        )
    ) as client:
        with pytest.raises(SourceError, match="unexpected_html$"):
            download(URL, Settings(), client)
    assert waits == []


def test_bad_compression_is_sanitized_and_not_retried(waits):
    stream = ChunkStream([b"secret invalid gzip"])
    with httpx.Client(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, headers={"content-encoding": "gzip"}, stream=stream)
        )
    ) as client:
        with pytest.raises(SourceError, match="invalid_response$") as caught:
            download(URL, Settings(), client)
    assert stream.closed
    assert waits == []
    assert "secret" not in "".join(traceback.format_exception(caught.value))


def test_protocol_error_is_sanitized(waits):
    def respond(request):
        raise httpx.RemoteProtocolError("secret malformed response", request=request)

    with httpx.Client(transport=httpx.MockTransport(respond)) as client:
        with pytest.raises(SourceError, match="invalid_response$") as caught:
            download(URL, Settings(), client)
    assert waits == []
    assert "secret" not in "".join(traceback.format_exception(caught.value))


def test_connection_error_is_sanitized_and_not_retried(waits):
    requests = []

    def respond(request):
        requests.append(request)
        raise httpx.ConnectError("secret TLS error", request=request)

    with httpx.Client(transport=httpx.MockTransport(respond)) as client:
        with pytest.raises(SourceError, match="request_failed$") as caught:
            download(URL, Settings(), client)
    assert len(requests) == 1
    assert waits == []
    assert "secret" not in "".join(traceback.format_exception(caught.value))


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "ftp://example.invalid/list",
        "not a URL",
        "https://host:secret",
        "http://example.invalid/list",
        "https://user:secret@example.invalid/list",
        "https://user@example.invalid/list",
        "https://:secret@example.invalid/list",
    ],
)
def test_invalid_or_insecure_url_is_rejected_without_request(url, waits):
    def respond(request):
        pytest.fail("invalid URL must not reach the transport")

    with httpx.Client(transport=httpx.MockTransport(respond)) as client:
        with pytest.raises(SourceError, match="invalid_url$"):
            download(url, Settings(), client)
    assert waits == []
