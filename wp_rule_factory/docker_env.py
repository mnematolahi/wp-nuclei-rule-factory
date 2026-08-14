"""Docker environment management for WP-Nuclei-Rule-Factory.

Provides an isolated WordPress + MySQL environment per test run using
the official Docker SDK for Python. Supports:
  • Context-manager protocol for guaranteed cleanup
  • Plugin/theme installation via WP-CLI
  • Health-check based readiness waiting
  • User creation for authenticated Nuclei scans
"""

import io
import os
import secrets
import tarfile
import time
import uuid
from typing import Any

# Lazy docker import — only when DockerEnvironment is actually instantiated
_docker = None
_NotFound = None
_APIError = None


def _ensure_docker():
    global _docker, _NotFound, _APIError
    if _docker is None:
        import docker as _d
        _docker = _d
        _NotFound = _d.errors.NotFound
        _APIError = _d.errors.APIError


from .utils import random_password


class DockerEnvironment:
    """Isolated WordPress + MySQL Docker stack for one test run."""

    def __init__(self, docker_image: str = "wordpress:latest",
                 mysql_image: str = "mysql:8.0",
                 database: str = "testdb",
                 startup_timeout: int = 120,
                 logger=None):
        self._docker_image = docker_image
        self._mysql_image = mysql_image
        self._database = database
        self._startup_timeout = startup_timeout
        self._logger = logger

        self._client: Any = None
        self._network: Any = None
        self._mysql_container: Any = None
        self._wp_container: Any = None

        self._network_name = f"wp_nuclei_{uuid.uuid4().hex[:8]}"
        self._mysql_password = random_password(16)
        self._mysql_root_password = random_password(16)
        self._wp_port = None

    # ── Context manager ────────────────────────────────────────
    def __enter__(self):
        _ensure_docker()
        self._client = _docker.from_env()
        try:
            self._setup()
        except Exception:
            self.cleanup()
            raise
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()
        return False

    # ── Setup ──────────────────────────────────────────────────
    def _setup(self):
        """Create network, MySQL, and WordPress containers."""
        self._client = self._client or _docker.from_env()

        # 1. Isolated network
        if self._logger:
            self._logger.info("SYSTEM", "docker", f"Creating network: {self._network_name}")
        self._network = self._client.networks.create(
            self._network_name, driver="bridge")

        # 2. MySQL container
        mysql_env = {
            "MYSQL_ROOT_PASSWORD": self._mysql_root_password,
            "MYSQL_DATABASE": self._database,
            "MYSQL_USER": "wpuser",
            "MYSQL_PASSWORD": self._mysql_password,
        }
        if self._logger:
            self._logger.info("SYSTEM", "docker", "Starting MySQL container...")
        self._mysql_container = self._client.containers.run(
            self._mysql_image,
            name=f"{self._network_name}_db",
            environment=mysql_env,
            network=self._network_name,
            detach=True,
            remove=True,
        )

        # 3. WordPress container
        wp_env = {
            "WORDPRESS_DB_HOST": f"{self._network_name}_db:3306",
            "WORDPRESS_DB_USER": "wpuser",
            "WORDPRESS_DB_PASSWORD": self._mysql_password,
            "WORDPRESS_DB_NAME": self._database,
        }
        if self._logger:
            self._logger.info("SYSTEM", "docker", "Starting WordPress container...")
        self._wp_container = self._client.containers.run(
            self._docker_image,
            name=f"{self._network_name}_wp",
            environment=wp_env,
            network=self._network_name,
            detach=True,
            remove=True,
            publish_all_ports=True,
        )

        # 4. Wait for readiness
        self._wait_ready()

    def _wait_ready(self):
        """Poll WordPress until it responds HTTP 200."""
        if self._logger:
            self._logger.info("SYSTEM", "docker",
                              f"Waiting for WordPress (timeout={self._startup_timeout}s)...")

        self._wp_container.reload()
        ports = self._wp_container.attrs["NetworkSettings"]["Ports"]
        tcp_ports = ports.get("80/tcp", [])
        if not tcp_ports or "HostPort" not in tcp_ports[0]:
            raise RuntimeError("WordPress container did not expose port 80")

        self._wp_port = int(tcp_ports[0]["HostPort"])

        start = time.monotonic()
        while time.monotonic() - start < self._startup_timeout:
            exit_code, output = self._wp_container.exec_run(
                "curl -s -L -o /dev/null -w '%{http_code}' http://localhost/",
                demux=True,
            )
            status_text = output[0].decode("utf-8", errors="ignore").strip() if output[0] else ""
            if "200" in status_text:
                if self._logger:
                    self._logger.info("SYSTEM", "docker", "WordPress is ready ✓")
                return
            time.sleep(2)

        raise TimeoutError(
            f"WordPress did not become ready within {self._startup_timeout}s"
        )

    # ── URL ────────────────────────────────────────────────────
    def get_url(self) -> str:
        """Return the reachable HTTP URL of the WordPress instance."""
        return f"http://localhost:{self._wp_port}"

    def get_internal_url(self) -> str:
        """Return the internal Docker network URL of the WordPress instance."""
        return f"http://{self.wp_container_name}:80"

    @property
    def network_name(self) -> str:
        """Return the Docker network name."""
        return self._network_name

    @property
    def wp_container_name(self) -> str:
        """Return the WordPress container name."""
        return f"{self._network_name}_wp"

    def get_container_ip(self) -> str:
        """Return the internal Docker network IP of the WordPress container."""
        self._wp_container.reload()
        networks = self._wp_container.attrs["NetworkSettings"]["Networks"]
        return networks[self._network_name]["IPAddress"]

    # ── WP-CLI ─────────────────────────────────────────────────
    def _wp_cli(self, *args: str) -> tuple[int, str, str]:
        """Run a wp-cli command inside the WordPress container."""
        cmd = f"wp {' '.join(args)} --allow-root 2>&1"
        exit_code, output = self._wp_container.exec_run(["bash", "-c", cmd])
        stdout = output.decode("utf-8", errors="ignore") if output else ""
        return exit_code, stdout

    def _ensure_wp_cli(self):
        """Make sure WP-CLI is available in the container."""
        exit_code, _ = self._wp_container.exec_run("which wp")
        if exit_code != 0:
            if self._logger:
                self._logger.info("SYSTEM", "docker", "Installing WP-CLI...")
            self._wp_container.exec_run([
                "bash", "-c",
                "curl -sSL https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar "
                "-o /usr/local/bin/wp && chmod +x /usr/local/bin/wp",
            ])

    def _ensure_wp_installed(self) -> bool:
        """Ensure WordPress core tables are present (installs on first run)."""
        self._ensure_wp_cli()
        exit_code, _ = self._wp_cli("core", "is-installed")
        if exit_code == 0:
            return True
        if self._logger:
            self._logger.info("SYSTEM", "docker", "Installing WordPress core (first run)...")
        ec, out = self._wp_cli(
            "core", "install",
            "--url=http://localhost",
            "--title=\"WP Nuclei Test\"",
            "--admin_user=wpadmin",
            "--admin_password=wpadmin",
            "--admin_email=wpadmin@test.local",
            "--skip-email",
        )
        if ec != 0 and self._logger:
            self._logger.error("SYSTEM", "docker", f"WordPress core install failed: {out}")
        return ec == 0

    # ── File Copy ──────────────────────────────────────────────────
    def _copy_file_to_container(self, src_path: str, dst_path: str) -> None:
        """Copy a local file into the container using a tar archive (put_archive)."""
        file_name = os.path.basename(dst_path)
        target_dir = os.path.dirname(dst_path) or "/"
        with open(src_path, "rb") as fh:
            data = fh.read()
        info = tarfile.TarInfo(name=file_name)
        info.size = len(data)
        tar_buf = io.BytesIO()
        with tarfile.open(fileobj=tar_buf, mode="w") as tar:
            tar.addfile(info, io.BytesIO(data))
        tar_buf.seek(0)
        self._wp_container.put_archive(target_dir, tar_buf)

    # ── Plugin / Theme Installation ─────────────────────────────
    def install_plugin(self, zip_path: str) -> bool:
        """Copy a plugin ZIP into the container and install it via WP-CLI."""
        self._ensure_wp_installed()
        container_path = f"/tmp/plugin_{uuid.uuid4().hex[:8]}.zip"

        # Copy zip into container
        if self._logger:
            self._logger.info("SYSTEM", "docker", f"Copying {zip_path} → {container_path}")
        self._copy_file_to_container(zip_path, container_path)

        # Install
        if self._logger:
            self._logger.info("SYSTEM", "docker", f"Installing plugin from {container_path}")
        exit_code, stdout = self._wp_cli("plugin", "install", container_path, "--activate")
        if exit_code != 0:
            if self._logger:
                self._logger.error("SYSTEM", "docker", f"Plugin install failed: {stdout}")
            return False
        return True

    def install_theme(self, zip_path: str) -> bool:
        """Copy a theme ZIP into the container and install it via WP-CLI."""
        self._ensure_wp_installed()
        container_path = f"/tmp/theme_{uuid.uuid4().hex[:8]}.zip"

        if self._logger:
            self._logger.info("SYSTEM", "docker", f"Copying {zip_path} → {container_path}")
        self._copy_file_to_container(zip_path, container_path)

        if self._logger:
            self._logger.info("SYSTEM", "docker", f"Installing theme from {container_path}")
        exit_code, stdout = self._wp_cli("theme", "install", container_path, "--activate")
        if exit_code != 0:
            if self._logger:
                self._logger.error("SYSTEM", "docker", f"Theme install failed: {stdout}")
            return False
        return True

    def install_plugin_or_theme(self, slug: str, zip_path: str,
                                 asset_type: str = "plugin") -> bool:
        """Install the asset as either plugin or theme based on type."""
        if asset_type == "theme":
            return self.install_theme(zip_path)
        return self.install_plugin(zip_path)

    # ── User Management (for authenticated scans) ───────────────
    def create_user(self, username: str, password: str,
                    role: str = "administrator") -> tuple[str, str] | None:
        """Create a WordPress user and return session cookies for Nuclei auth."""
        self._ensure_wp_cli()
        if self._logger:
            self._logger.info("SYSTEM", "docker",
                              f"Creating user: {username} ({role})")
        exit_code, stdout = self._wp_cli(
            "user", "create", username, f"{username}@test.local",
            f"--user_pass={password}", f"--role={role}"
        )
        if exit_code != 0:
            if self._logger:
                self._logger.error("SYSTEM", "docker",
                                   f"User creation failed: {stdout}")
            return None

        # Login to get cookies
        exit_code2, stdout2 = self._wp_container.exec_run(
            f'curl -s -c /tmp/cookies.txt -X POST "http://localhost/wp-login.php" '
            f'--data-urlencode "log={username}" '
            f'--data-urlencode "pwd={password}" '
            f'--data-urlencode "wp-submit=Log+In" '
            f'--data-urlencode "testcookie=1" -L -o /dev/null -w "%{http_code}"'
        )
        if stdout2 and b"200" not in stdout2:
            # Try to extract cookies
            exit_code3, cookies_raw = self._wp_container.exec_run(
                ["bash", "-c", "cat /tmp/cookies.txt 2>/dev/null"]
            )
            if cookies_raw:
                return cookies_raw.decode("utf-8", errors="ignore")
            return None

        exit_code3, cookies_raw = self._wp_container.exec_run(
            ["bash", "-c", "cat /tmp/cookies.txt 2>/dev/null"]
        )
        if cookies_raw:
            cookies_text = cookies_raw.decode("utf-8", errors="ignore")
            # Parse to cookie header string
            cookie_header = "; ".join(
                line.split("\t")[-1].strip()
                for line in cookies_text.strip().splitlines()
                if not line.startswith("#") and line.strip()
            )
            return cookie_header
        return None

    # ── Cleanup ────────────────────────────────────────────────
    def cleanup(self):
        """Remove all Docker resources. Safe to call multiple times."""
        if self._logger:
            self._logger.info("SYSTEM", "docker", "Cleaning up Docker environment...")

        for resource, name in [
            (self._wp_container, "WordPress"),
            (self._mysql_container, "MySQL"),
        ]:
            if resource:
                try:
                    resource.remove(force=True)
                except (_NotFound, _APIError):
                    pass

        if self._network:
            try:
                self._network.remove()
            except (_NotFound, _APIError):
                pass

        self._wp_container = None
        self._mysql_container = None
        self._network = None
