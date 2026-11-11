"""外部内容预览（SSRF 防护）。"""

import ipaddress
import socket
import urllib.parse
import urllib.request

_ALLOWED_SCHEMES = {"http", "https"}


def _validate_url(url: str) -> None:
    """只允许 http/https，且目标地址不得是内网/回环/保留地址。"""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme.lower() not in _ALLOWED_SCHEMES:
        raise ValueError(f"scheme not allowed: {parsed.scheme!r}")
    host = parsed.hostname
    if not host:
        raise ValueError("missing host")
    try:
        infos = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80))
    except socket.gaierror:
        raise ValueError(f"unresolvable host: {host!r}") from None
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            raise ValueError(f"target address not allowed: {ip}")


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """重定向目标同样要过校验，防止 302 跳到内网。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _validate_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_SafeRedirectHandler())


def fetch_preview(url: str, timeout: float = 5.0) -> str:
    _validate_url(url)
    with _OPENER.open(url, timeout=timeout) as response:
        data = response.read(2048)
    return data.decode("utf-8", "replace")
