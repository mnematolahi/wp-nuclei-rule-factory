"""Docker environment management via CLI subprocess.

Replaces docker Python SDK with direct docker CLI calls.
Supports context-manager protocol with guaranteed cleanup.
"""

import os
import subprocess
import tempfile
import time
import uuid
from typing import Any


class DockerEnvironment:
    """Isolated WordPress + MySQL stack via docker CLI."""

    def __init__(
        self,
        docker_image: str = "wordpress:latest",
        mysql_image: str = "mysql:8.0",
        database: str = "testdb",
        startup_timeout: int = 120,
        logger=None,
    ):
        self._docker_image = docker_image
        self._mysql_image = mysql_image
        self._database = database
        self._startup_timeout = startup_timeout
        self._logger = logger

        self._network_name: str | None = None
        self._mysql_container: str | None = None
        self._wp_container: str | None = None
        self._wp_port: int | None = None

    def __enter__(self):
        self._setup()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()
        return False

    # ── helpers ──────────────────────────────────────────────────
    def _cli(self, *args: str, timeout: int = 60) -> subprocess.CompletedProcess:
        cmd = ["docker", *args]
        if self._logger:
            self._logger.info("SYSTEM", "docker", f"CLI: {cmd}")
        return subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )

    def _running(self) -> bool:
        r = self._cli("inspect", "-f", "{{.State.Running}}", self._wp_container)
        return r.stdout.strip() == "true"

    # ── setup ────────────────────────────────────────────────────
    def _setup(self):
        self._network_name = f"wp_nuclei_{uuid.uuid4().hex[:8]}"
        self._mysql_container = f"{self._network_name}_db"
        self._wp_container = f"{self._network_name}_wp"

        if self._logger:
            self._logger.info("SYSTEM", "docker", f"Creating network: {self._network_name}")
        network = self._cli("network", "create", self._network_name)
        if network.returncode != 0:
            raise RuntimeError(f"docker network create failed: {network.stderr.strip()}")

        # WordPress must use the *same* credentials with which MySQL was
        # initialized.  Generating these independently makes every test
        # environment fail with "Error establishing a database connection".
        db_root_password = _random(16)
        db_password = _random(16)

        # MySQL
        mysql_env = (
            "-e", "MYSQL_ROOT_PASSWORD=" + db_root_password,
            "-e", "MYSQL_DATABASE=" + self._database,
            "-e", "MYSQL_USER=wpuser",
            "-e", "MYSQL_PASSWORD=" + db_password,
        )
        if self._logger:
            self._logger.info("SYSTEM", "docker", "Starting MySQL container...")
        mysql_result = self._cli(
            "run", "-d", "--name", self._mysql_container,
            *mysql_env, "--network", self._network_name,
            self._mysql_image,
        )
        if mysql_result.returncode != 0:
            self.cleanup()
            raise RuntimeError(f"MySQL failed to start: {mysql_result.stderr.strip()}")

        # WordPress
        wp_env = (
            "-e", "WORDPRESS_DB_HOST=" + self._mysql_container + ":3306",
            "-e", "WORDPRESS_DB_USER=wpuser",
            "-e", "WORDPRESS_DB_PASSWORD=" + db_password,
            "-e", "WORDPRESS_DB_NAME=" + self._database,
            "-p", "0:80",
            "-d", "--name", self._wp_container,
            "--network", self._network_name,
            self._docker_image,
        )
        if self._logger:
            self._logger.info("SYSTEM", "docker", "Starting WordPress container...")
        result = self._cli("run", *wp_env)
        if result.returncode != 0:
            self.cleanup()
            raise RuntimeError(f"docker run failed: {result.stderr}")

        # Wait for WP ready
        self._wait_ready()

    def _wait_ready(self):
        if self._logger:
            self._logger.info("SYSTEM", "docker", f"Waiting for WP (timeout={self._startup_timeout}s)...")

        start = time.monotonic()
        while time.monotonic() - start < self._startup_timeout:
            # Find the exposed host port
            r = self._cli("inspect", "-f", "{{range .NetworkSettings.Ports}}{{(index . 0).HostPort}}{{end}}", self._wp_container, timeout=5)
            port_str = r.stdout.strip()
            if not port_str:
                time.sleep(2)
                continue
            self._wp_port = int(port_str)

            # A HTTP response alone is insufficient: WordPress returns an
            # error page with HTTP 200 when its database is unavailable.
            check = self._cli(
                "exec", self._wp_container,
                "sh", "-c", "curl -fsS --max-time 5 http://localhost/ 2>/dev/null || echo FAIL",
                timeout=15,
            )
            body = check.stdout
            if (check.returncode == 0 and "FAIL" not in body
                    and "Error establishing a database connection" not in body):
                if self._logger:
                    self._logger.info("SYSTEM", "docker", f"WordPress ready on port {self._wp_port}")
                return
            time.sleep(2)

        self.cleanup()
        raise TimeoutError(f"WordPress did not become ready within {self._startup_timeout}s")

    # ── public accessors ─────────────────────────────────────────
    def get_url(self) -> str:
        if not self._wp_port:
            raise RuntimeError("Environment not ready")
        return f"http://localhost:{self._wp_port}"

    @property
    def network_name(self) -> str:
        return self._network_name or ""

    @property
    def wp_container_name(self) -> str:
        return self._wp_container or ""

    # ── wp-cli helper (exec into container) ──────────────────────
    def _wp_cli(self, *args: str) -> tuple[int, str]:
        check = self._cli("exec", self._wp_container, "sh", "-c",
                          "command -v wp >/dev/null 2>&1", timeout=10)
        if check.returncode != 0:
            # Copy the official CLI phar from wordpress:cli.  This avoids a
            # runtime GitHub download in each test container and works in
            # restricted Docker networks as long as the image is available.
            helper = f"{self._wp_container}_cli"
            tmp_path = None
            try:
                self._cli("rm", "-f", helper, timeout=10)
                create = self._cli("create", "--name", helper,
                                   "wordpress:cli", timeout=120)
                if create.returncode != 0:
                    return create.returncode, create.stderr + create.stdout
                with tempfile.NamedTemporaryFile(delete=False) as tmp:
                    tmp_path = tmp.name
                copy_out = self._cli("cp", f"{helper}:/usr/local/bin/wp", tmp_path,
                                     timeout=60)
                if copy_out.returncode != 0:
                    return copy_out.returncode, copy_out.stderr + copy_out.stdout
                copy_in = self._cli("cp", tmp_path,
                                    f"{self._wp_container}:/usr/local/bin/wp", timeout=60)
                if copy_in.returncode != 0:
                    return copy_in.returncode, copy_in.stderr + copy_in.stdout
                chmod = self._cli("exec", self._wp_container, "chmod", "+x",
                                  "/usr/local/bin/wp", timeout=10)
                if chmod.returncode != 0:
                    return chmod.returncode, chmod.stderr + chmod.stdout
            finally:
                self._cli("rm", "-f", helper, timeout=10)
                if tmp_path:
                    try:
                        os.unlink(tmp_path)
                    except OSError:
                        pass
        if self._logger:
            self._logger.info("SYSTEM", "docker", f"wp-cli: {args}")
        result = self._cli("exec", self._wp_container, "wp", *args, "--allow-root", timeout=60)
        return result.returncode, result.stderr + result.stdout

    def _ensure_wp_installed(self) -> bool:
        ec, _ = self._wp_cli("core", "is-installed")
        if ec == 0:
            return True
        if self._logger:
            self._logger.info("SYSTEM", "docker", "Installing WordPress core...")
        ec, out = self._wp_cli(
            "core", "install",
            "--url=http://localhost",
            "--title=\"WP Test\"",
            "--admin_user=admin",
            "--admin_password=admin",
            "--admin_email=admin@test.local",
            "--skip-email",
        )
        return ec == 0

    # ── plugin/theme install ─────────────────────────────────────
    def install_plugin(self, zip_path: str) -> bool:
        absp = os.path.abspath(zip_path)
        if not os.path.exists(absp):
            raise FileNotFoundError(zip_path)

        if self._logger:
            self._logger.info("SYSTEM", "docker", f"Copying {zip_path} to container")

        tmp_in_container = f"/tmp/plugin_{uuid.uuid4().hex[:8]}.zip"

        # docker cp
        cp = self._cli("cp", absp, f"{self._wp_container}:{tmp_in_container}", timeout=120)
        if cp.returncode != 0:
            if self._logger:
                self._logger.error("SYSTEM", "docker", f"docker cp failed: {cp.stderr}")
            return False

        if not self._ensure_wp_installed():
            if self._logger:
                self._logger.error("SYSTEM", "docker", "WordPress core installation failed")
            return False

        if self._logger:
            self._logger.info("SYSTEM", "docker", f"Installing plugin from {tmp_in_container}")
        ec, out = self._wp_cli("plugin", "install", tmp_in_container, "--activate")
        if ec != 0:
            if self._logger:
                self._logger.error("SYSTEM", "docker", f"Plugin install failed: {out}")
            return False
        return True

    def install_theme(self, zip_path: str) -> bool:
        absp = os.path.abspath(zip_path)
        if not os.path.exists(absp):
            raise FileNotFoundError(zip_path)

        if self._logger:
            self._logger.info("SYSTEM", "docker", f"Copying {zip_path} to container")

        tmp_in_container = f"/tmp/theme_{uuid.uuid4().hex[:8]}.zip"
        cp = self._cli("cp", absp, f"{self._wp_container}:{tmp_in_container}", timeout=120)
        if cp.returncode != 0:
            if self._logger:
                self._logger.error("SYSTEM", "docker", f"docker cp failed")
            return False

        if not self._ensure_wp_installed():
            if self._logger:
                self._logger.error("SYSTEM", "docker", "WordPress core installation failed")
            return False

        ec, out = self._wp_cli("theme", "install", tmp_in_container, "--activate")
        if ec != 0:
            if self._logger:
                self._logger.error("SYSTEM", "docker", f"Theme install failed: {out}")
            return False
        return True

    def install_plugin_or_theme(self, slug: str, zip_path: str,
                                 asset_type: str = "plugin") -> bool:
        if asset_type == "theme":
            return self.install_theme(zip_path)
        return self.install_plugin(zip_path)

    # ── user creation (for auth scans) ───────────────────────────
    def create_user(self, username: str, password: str,
                    role: str = "administrator"):
        self._ensure_wp_installed()
        if self._logger:
            self._logger.info("SYSTEM", "docker", f"Creating user: {username}")
        ec, out = self._wp_cli(
            "user", "create", username,
            f"{username}@test.local",
            f"--user_pass={password}",
            f"--role={role}",
        )
        if ec != 0:
            if self._logger:
                self._logger.error("SYSTEM", "docker", f"User creation failed: {out}")
            return None

        # Login via curl inside container
        r = self._cli(
            "exec", self._wp_container, "sh", "-c",
            f'curl -s -c /tmp/cookies.txt -X POST http://localhost/wp-login.php '
            f'--data-urlencode "log={username}" '
            f'--data-urlencode "pwd={password}" '
            f'--data-urlencode "wp-submit=Log+In" '
            f'--data-urlencode "testcookie=1" -L -o /dev/null -w "%{{http_code}}"',
            timeout=30,
        )
        if "200" not in r.stdout:
            return None

        cr = self._cli("exec", self._wp_container, "cat", "/tmp/cookies.txt", timeout=10)
        if cr.returncode != 0:
            return None
        cookies = []
        for line in cr.stdout.splitlines():
            # curl's cookie jar is Netscape format; #HttpOnly_ is still a
            # valid cookie record and must not be discarded.
            line = line.removeprefix("#HttpOnly_")
            if not line or line.startswith("#"):
                continue
            fields = line.split("\t")
            if len(fields) >= 7:
                cookies.append(f"{fields[5]}={fields[6]}")
        return "; ".join(cookies) or None
        cr = self._cli("exec", self._wp_container, "cat", "/tmp/cookies.txt", timeout=10)
        if cr.returncode == 0:
            cookies_text = cr.stdout
            header_parts = []
            for line in cookies_text.strip().splitlines():
                if not line.startswith("#") and "\t" in line:
                    cookie_val = line.split("\t")[-1].strip()
                    if cookie_val and "=" in cookie_val:
                        header_parts.append(cookie_val)
            return "; ".join(header_parts) if header_parts else None
        return None

    # ── cleanup ──────────────────────────────────────────────────
    def cleanup(self):
        if self._logger:
            self._logger.info("SYSTEM", "docker", "Cleaning up Docker environment...")

        for name in (self._wp_container, self._mysql_container):
            if name:
                try:
                    self._cli("rm", "-f", name, timeout=20)
                except Exception:
                    pass

        if self._network_name:
            try:
                self._cli("network", "rm", self._network_name, timeout=10)
            except Exception:
                pass

        self._wp_container = None
        self._mysql_container = None
        self._network_name = None
        self._wp_port = None


def _random(n: int) -> str:
    import secrets
    charset = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(secrets.choice(charset) for _ in range(n))
