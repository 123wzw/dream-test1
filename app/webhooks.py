"""外部内容预览。"""

import urllib.request


def fetch_preview(url: str, timeout: float = 5.0) -> str:
    with urllib.request.urlopen(url, timeout=timeout) as response:
        data = response.read(2048)
    return data.decode("utf-8", "replace")
