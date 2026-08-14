"""WordPress.org repository downloader.

Validates and downloads specific plugin/theme versions from the official
WordPress.org repository. Supports:
  • Plugin downloads: https://downloads.wordpress.org/plugin/{slug}.{version}.zip
  • Theme downloads: https://downloads.wordpress.org/theme/{slug}.{version}.zip
  • HEAD-based pre-validation
  • SHA-256 hash computation
  • Rate limiting & retry logic
"""

import hashlib
import os
import tempfile
import time

import requests


class WordPressRepo:
    """Downloader for WordPress.org plugin / theme ZIPs."""

    def __init__(self, plugin_url_template: str, theme_url_template: str,
                 plugin_info_url: str, delay: float = 1.0,
                 max_retries: int = 3, backoff: float = 2.0, logger=None):
        self._plugin_url_t = plugin_url_template
        self._theme_url_t = theme_url_template
        self._plugin_info_url = plugin_info_url
        self._delay = delay
        self._max_retries = max_retries
        self._backoff = backoff
        self._logger = logger
        self._last_request = 0.0

    def _wait_rate(self):
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self._delay:
            time.sleep(self._delay - elapsed)
        self._last_request = time.monotonic()

    def _retry_request(self, method: str, url: str, **kwargs):
        """Make an HTTP request with retries and rate limiting."""
        session = kwargs.pop("_session", requests)
        self._wait_rate()

        for attempt in range(1, self._max_retries + 1):
            try:
                resp = session.request(method, url, timeout=30, **kwargs)
                if resp.status_code in (429, 503):
                    wait = self._backoff ** attempt
                    if self._logger:
                        self._logger.warn("SYSTEM", "download",
                                          f"HTTP {resp.status_code} on {url}, retrying in {wait}s")
                    time.sleep(wait + self._delay)
                    continue
                return resp
            except requests.exceptions.RequestException as exc:
                if self._logger:
                    self._logger.warn("SYSTEM", "download",
                                      f"Request error on {url}: {exc}")
                if attempt < self._max_retries:
                    time.sleep(self._backoff ** attempt + self._delay)
                else:
                    raise
        return None

    def _build_download_url(self, slug: str, version: str,
                            asset_type: str = "plugin") -> str:
        """Build the correct WordPress.org download URL."""
        template = self._theme_url_t if asset_type == "theme" else self._plugin_url_t
        return template.format(slug=slug, version=version)

    def _validate_url(self, url: str) -> bool:
        """HEAD-request the URL to check it exists before full download."""
        try:
            resp = self._retry_request("HEAD", url, allow_redirects=True)
            return resp is not None and resp.status_code == 200
        except Exception:
            return False

    def _compute_sha256(self, file_path: str) -> str:
        """Compute SHA-256 hash of a file."""
        sha = hashlib.sha256()
        with open(file_path, "rb") as fh:
            while True:
                chunk = fh.read(8192)
                if not chunk:
                    break
                sha.update(chunk)
        return sha.hexdigest()

    def download_version(self, slug: str, version: str,
                         asset_type: str = "plugin") -> tuple[str | None, str]:
        """Download a specific version ZIP from WordPress.org.

        Parameters
        ----------
        slug : str
            Plugin/theme slug.
        version : str
            Exact version string (e.g. "2.3.1").
        asset_type : str
            "plugin" or "theme".

        Returns
        -------
        (path, sha256)
            path — absolute path to the downloaded ZIP, or None on failure.
            sha256 — hexadecimal SHA-256 hash, or empty string on failure.
        """
        url = self._build_download_url(slug, version, asset_type)

        if self._logger:
            self._logger.info("SYSTEM", "download", f"Validating: {url}")

        # Pre-validate
        if not self._validate_url(url):
            if self._logger:
                self._logger.warn("SYSTEM", "download",
                                  f"URL not found (HEAD check failed): {url}")
            return None, ""

        # Download to temp file
        if self._logger:
            self._logger.info("SYSTEM", "download", f"Downloading: {url}")

        try:
            resp = self._retry_request("GET", url, allow_redirects=True)
            if resp is None or resp.status_code != 200:
                if self._logger:
                    self._logger.error("SYSTEM", "download",
                                       f"Download failed for {url}")
                return None, ""

            # Store to permanent location for packaging
            safe_name = f"{slug}_{version}.zip"
            out_path = os.path.join(tempfile.gettempdir(), safe_name)

            with open(out_path, "wb") as fh:
                fh.write(resp.content)

            sha256 = self._compute_sha256(out_path)

            if self._logger:
                size_mb = len(resp.content) / (1024 * 1024)
                self._logger.info("SYSTEM", "download",
                                  f"Downloaded: {safe_name} ({size_mb:.2f} MB, SHA256={sha256[:16]}…)")

            return out_path, sha256

        except Exception as exc:
            if self._logger:
                self._logger.error("SYSTEM", "download",
                                   f"Exception downloading {url}: {exc}")
            return None, ""

    def try_download_theme_fallback(self, slug: str, version: str) -> tuple[str | None, str]:
        """If a plugin download failed, try as a theme. Returns (path, sha256)."""
        return self.download_version(slug, version, asset_type="theme")
