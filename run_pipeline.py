#!/usr/bin/env python3
"""WP-Nuclei Test Runner — spin up Docker WP, install plugins, run nuclei, clean up.

Uses docker CLI (subprocess) instead of Docker SDK.
WP-CLI installed inside wordpress:latest container.

Usage:
    python run_pipeline.py --yaml-dir ./test_yamls
    python run_pipeline.py --yaml-dir ./nuclei-templates/cve-less/plugins
    python run_pipeline.py --yaml-dir ./test_yamls --verbose
    python run_pipeline.py --yaml-dir ./test_yamls --nuclei "C:/Users/NEMATO~1/go/bin/nuclei.exe"
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
import uuid


# ====================== helpers ======================

def cli(*args, timeout=60, hide=False):
    """Run a docker CLI command. Returns (returncode, stdout, stderr)."""
    cmd = ["docker", *args]
    if not hide:
        print(f"  > docker {' '.join(args)}")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired:
        return 1, "", "timeout(%d s)" % timeout
    except Exception as e:
        return 1, "", str(e)


def random_name():
    return "wpnf_%s" % uuid.uuid4().hex[:8]


# ====================== yaml parser ======================

def parse_simple_yaml(path):
    """Return metadata dict from a nuclei YAML."""
    try:
        import yaml as _yaml
        with open(os.path.abspath(path), "r", encoding="utf-8") as fh:
            data = _yaml.safe_load(fh)
    except Exception:
        return None

    if not data or not isinstance(data, dict):
        return None

    rule_id = data.get("id", "unknown")
    if isinstance(rule_id, dict):
        rule_id = rule_id.get("id", "unknown")
    rule_id = str(rule_id).replace(" ", "_")

    info = data.get("info", {}) or {}
    name = str(info.get("name", ""))
    severity = str(info.get("severity", ""))

    meta = info.get("metadata", {}) or {}
    slug = str(meta.get("slug", "")) or str(meta.get("plugin", ""))

    # Also check variables
    if not slug:
        for k in ("slug", "plugin", "target_slug", "wp_slug"):
            if k in data.get("variables", {}):
                slug = str(data["variables"][k])
                break

    # Check tags for wp-plugin slug
    if not slug:
        tags = info.get("tags", "")
        if tags:
            if isinstance(tags, str):
                tags = [t.strip() for t in tags.split(",")]
            generic_tags = {
                "cve", "wordpress", "wp-plugin", "wp-theme", "production",
                "medium", "low", "high", "critical", "info", "local", "network",
                "manual", "panel", "default-logins", "misconfig", "exposure",
                "iot", "mask", "tech", "microsoft", "jira", "grafana", "tomcat",
                "jenkins", "wordpress-core", "wordpress-themes", "wordpress-plugins",
                "rce", "sqli", "xss", "csrf", "lfi", "rfi", "ssrf", "dos",
                "unauth", "auth", "sensitive", "default",
            }
            for tag in tags:
                tag = tag.strip().lower()
                if tag and tag not in generic_tags:
                    slug = tag
                    break

    # Try name heuristics (e.g. "Analytics Insights")
    if not slug:
        words = name.split()
        if words:
            slug = "-".join(w.lower() for w in words)

    if not slug:
        bname = os.path.basename(path)
        slug = bname.split("-")[0] if bname else "unknown"

    vuln_ver = str(meta.get("vulnerable_version", ""))
    if not vuln_ver:
        for k in ("vulnerable_version", "vuln_version", "affected_version",
                   "vulnerable", "affected"):
            if k in data.get("variables", {}):
                vuln_ver = str(data["variables"][k])
    if not vuln_ver:
        import re as _r
        m = _r.search(r"(<=|<|=)\s*([0-9]+(?:\.[0-9]+)*)", name)
        if m:
            vuln_ver = "%s %s" % (m.group(1), m.group(2))

    patch_ver = str(meta.get("patched_version", ""))
    if not patch_ver:
        for k in ("patched_version", "safe_version", "fixed_version"):
            if k in data.get("variables", {}):
                patch_ver = str(data["variables"][k])

    return {
        "rule_id": rule_id,
        "name": name,
        "severity": severity,
        "slug": slug,
        "vulnerable_version": vuln_ver,
        "patched_version": patch_ver,
        "yaml_path": os.path.abspath(path),
    }


# ====================== docker env via CLI ======================

class DockerEnv:
    """Manage WordPress + MySQL containers via docker CLI.
    
    Strategy:
    1. Mount volume to share files between containers
    2. Use alpine container to extract zip into volume
    3. Use wordpress:cli container (has wp-cli + network access) to install plugin
    """

    def __init__(self, verbose=False):
        self.prefix = random_name()
        self.net = "%s_net" % self.prefix
        self.mysql = "%s_db" % self.prefix
        self.wp = "%s_wp" % self.prefix
        self.volume = "%s_vol" % self.prefix
        self.port = None
        self.verbose = verbose

    def __enter__(self):
        if not self.start():
            raise RuntimeError("Docker environment failed to start")
        return self

    def __exit__(self, *exc):
        self.teardown()
        return False

    def _run(self, *args, timeout=60):
        return cli(*args, timeout=timeout, hide=not self.verbose)

    def start(self):
        # clean up stale containers/networks/volumes from previous runs
        self.teardown()

        if self.verbose:
            print("  Prefix: %s" % self.prefix)

        # 1. create network
        code, _, err = self._run("network", "create", self.net, timeout=10)
        if code != 0:
            print("  ERROR: network create failed: " + err)
            return False

        # 2. create volume
        code, _, err = self._run("volume", "create", self.volume, timeout=10)
        if code != 0:
            print("  ERROR: volume create failed: " + err)
            self._run("network", "rm", self.net, timeout=5, hide=True)
            return False

        if self.verbose:
            print("  Volume: %s" % self.volume)

        # 3. run MySQL
        code, _, err = self._run(
            "run", "-d", "-m", "512m", "--cpus", "1",
            "--name", self.mysql,
            "-e", "MYSQL_ROOT_PASSWORD=rootpass",
            "-e", "MYSQL_DATABASE=testdb",
            "-e", "MYSQL_USER=wpuser", "-e", "MYSQL_PASSWORD=wppass",
            "--network", self.net,
            "mysql:8.0",
            timeout=30,
        )
        if code != 0:
            print("  ERROR: MySQL failed: " + err)
            self.teardown()
            return False

        if self.verbose:
            print("  MySQL started: %s" % self.mysql)

        # 4. run WordPress
        code, _, err = self._run(
            "run", "-d", "-m", "512m", "--cpus", "1",
            "-p", "0:80",
            "--name", self.wp,
            "-e", "WORDPRESS_DB_HOST=" + self.mysql + ":3306",
            "-e", "WORDPRESS_DB_USER=wpuser",
            "-e", "WORDPRESS_DB_PASSWORD=wppass",
            "-e", "WORDPRESS_DB_NAME=testdb",
            "--network", self.net,
            "-v", self.volume + ":/var/www/html",
            "wordpress:latest",
            timeout=30,
        )
        if code != 0:
            print("  ERROR: WP failed: " + err)
            self.teardown()
            return False

        if self.verbose:
            print("  WP started: %s" % self.wp)

        # 5. find port
        code, out, _ = self._run("inspect", "-f",
            "{{range .NetworkSettings.Ports}}{{(index . 0).HostPort}}{{end}}",
            self.wp, timeout=5)
        if code != 0 or not out:
            print("  ERROR: cannot find WP port")
            self.teardown()
            return False
        self.port = int(out)

        # 6. wait for WP ready
        if self.verbose:
            print("  Waiting for WP on port %d ..." % self.port)
        for i in range(60):  # max 60 retries = 2 min
            code, stdout_data, _ = self._run(
                "exec", self.wp, "sh", "-c",
                "wget -qO- -t1 -T5 http://localhost/ > /dev/null 2>&1 || echo NO",
                timeout=15)
            combined = "%s%s" % (stdout_data or "", code or "")
            if "NO" not in combined:
                print("  WP ready on port %d" % self.port)
                return True
            time.sleep(2)

        print("  ERROR: WP timed out (2 min)")
        self.teardown()
        return False

    def _extract_zip_to_volume(self, zip_path, dest_dir):
        """Copy a zip file into a temp container, extract it into our volume."""
        zip_name = os.path.basename(zip_path)
        tmp_ctr = "cp_%s" % uuid.uuid4().hex[:6]

        # Clean up old tmp containers
        self._run("rm", "-f", tmp_ctr, timeout=5, hide=True)

        # Create a temp Alpine container that has BOTH the host dir and the volume
        # On Windows/Docker Desktop, we use absolute Windows path for -v
        host_dir = os.path.dirname(os.path.abspath(zip_path))
        host_base = os.path.basename(zip_path)

        code, _, err = self._run(
            "create",
            "-v", self.volume + ":/data:rw",
            "-v", host_dir + ":/src:ro",
            "--name", tmp_ctr,
            "alpine", "sh", "hide=True")

        if code != 0:
            # On Windows, bind mounts might fail. Fall back to docker cp approach.
            if self.verbose:
                print("    Bind mount failed, trying docker cp fallback...")
            return self._extract_zip_cp(zip_path, dest_dir)

        # Copy zip file into the volume
        code, _, _ = self._run(
            "start", "-a", tmp_ctr,
            "sh", "-c", "cp /src/%s /data/%s" % (host_base, zip_name),
            timeout=30)

        self._run("rm", "-f", tmp_ctr, timeout=10, hide=True)

        if code != 0:
            if self.verbose:
                print("    Alpine copy failed, trying wget fallback...")
            return self._extract_zip_wget(zip_path, dest_dir)

        return True

    def _extract_zip_cp(self, zip_path, dest_dir):
        """Fallback: use docker cp to copy zip to a temp container, then to volume."""
        tmp_src = "cp_src_%s" % uuid.uuid4().hex[:6]
        tmp_dst = "cp_dst_%s" % uuid.uuid4().hex[:6]

        self._run("rm", "-f", tmp_src, "-f", tmp_dst, timeout=5, hide=True)

        # Create a container with both volumes
        code, _, _ = self._run(
            "create",
            "-v", self.volume + ":/dst:rw",
            "--name", tmp_dst,
            "alpine", "sh", hide=True)

        self._run("rm", "-f", tmp_src, timeout=5, hide=True)
        code, _, _ = self._run(
            "create",
            "-v", os.path.dirname(os.path.abspath(zip_path)) + ":/src:ro",
            "-v", host_dir + ":/shared:ro",
            "--name", tmp_src,
            "alpine", "sh", hide=True)

        # Actually, just use docker cp directly. On Windows it should work with UNC paths.
        self._run("rm", "-f", tmp_src, tmp_dst, timeout=10, hide=True)

        # Better fallback: use docker cp
        code, _, _ = self._run("cp", os.path.abspath(zip_path), "/dev/null", hide=True)

        # Last fallback: use wget inside the container
        return self._extract_zip_wget(zip_path, dest_dir)

    def _extract_zip_wget(self, zip_path, dest_dir):
        """Fallback: download zip directly from WP.org or use local path via container."""
        if not os.path.exists(zip_path):
            print("    Fallback failed: file not found")
            return False

        # Use a container to read the file and send it
        tmp_ctr = "fetch_%s" % uuid.uuid4().hex[:6]
        self._run("rm", "-f", tmp_ctr, timeout=5, hide=True)

        host_dir = os.path.dirname(os.path.abspath(zip_path))
        host_base = os.path.basename(zip_path)

        # On Docker Desktop for Windows, named pipe / local socket allows docker cp
        code, _, _ = self._run(
            "create",
            "-v", self.volume + ":/data:rw",
            "--name", tmp_ctr,
            "alpine", "sh", hide=True)

        # Try to copy via docker cp (this is what Windows Docker Desktop supports)
        code, _, _ = self._run("rm", "-f", tmp_ctr, timeout=5, hide=True)

        return False

    def install_plugin(self, zip_path):
        """Install a plugin using wordpress:cli container with volume."""
        zip_name = "%s_plugin.zip" % self.prefix

        # Step 1: Copy zip into the shared volume
        # On Windows, use a container to read the file
        src_ctr = "src_%s" % uuid.uuid4().hex[:6]
        dst_ctr = "dst_%s" % uuid.uuid4().hex[:6]
        self._run("rm", "-f", src_ctr, timeout=5, hide=True)
        self._run("rm", "-f", dst_ctr, timeout=5, hide=True)

        host_dir = os.path.dirname(os.path.abspath(zip_path))
        host_base = os.path.basename(zip_path)

        # Create source container with host dir
        code, _, _ = self._run(
            "create",
            "-v", host_dir + ":/src:ro",
            "-v", self.volume + ":/vol:rw",
            "--name", src_ctr,
            "alpine", "sh", "-c", "cp /src/%s /vol/%s" % (host_base, zip_name),
            timeout=30)

        if code != 0:
            # Fallback: try with different mount format
            self._run("rm", "-f", src_ctr, timeout=5, hide=True)
            # Use docker cp approach
            code, _, _ = self._run("rm", "-f", dst_ctr, timeout=5, hide=True)
            code, _, _ = self._run(
                "create",
                "-v", self.volume + ":/vol:rw",
                "--name", dst_ctr,
                "alpine", "sh", hide=True)
            code, _, _ = self._run("cp", os.path.abspath(zip_path),
                                    "dst_ctr:/vol/%s" % zip_name, timeout=120)
            if code != 0:
                self._run("rm", "-f", dst_ctr, timeout=5, hide=True)
                print("    Copy failed")
                return False
        else:
            # Cleanup: remove the source container
            self._run("rm", "-f", src_ctr, timeout=5, hide=True)

        if self.verbose:
            print("    Zip placed in volume")

        # Step 2: Run WP-CLI to install the plugin
        cli_ctr = "wpcli_%s" % uuid.uuid4().hex[:6]
        self._run("rm", "-f", cli_ctr, timeout=5, hide=True)

        code, out, err = self._run(
            "run", "--rm",
            "-v", self.volume + ":/var/www/html:rw",
            "--network", self.net,
            "-e", "WORDPRESS_DB_HOST=" + self.mysql + ":3306",
            "-e", "WORDPRESS_DB_USER=wpuser",
            "-e", "WORDPRESS_DB_PASSWORD=wppass",
            "-e", "WORDPRESS_DB_NAME=testdb",
            "--name", cli_ctr,
            "wordpress:cli",
            "wp", "plugin", "install",
            "/var/www/html/wp-content/plugins/%s" % zip_name,
            "--force", "--activate", "--allow-root",
            timeout=120)

        if code != 0:
            print("    wp plugin install failed:")
            if self.verbose:
                for line in (out + "\n" + err).split("\n")[:40]:
                    if line:
                        print("      " + line)
            return False

        if self.verbose:
            print("    Plugin installed OK")
        return True

    def install_theme(self, zip_path, dest_dir="theme"):
        """Install a theme via wordpress:cli container with volume."""
        zip_name = "%s_theme.zip" % self.prefix

        # Same copy mechanism as plugin
        src_ctr = "src_%s" % uuid.uuid4().hex[:6]
        self._run("rm", "-f", src_ctr, timeout=5, hide=True)

        host_dir = os.path.dirname(os.path.abspath(zip_path))
        host_base = os.path.basename(zip_path)

        code, _, _ = self._run(
            "create",
            "-v", host_dir + ":/src:ro",
            "-v", self.volume + ":/vol:rw",
            "--name", src_ctr,
            "alpine", "sh", "-c", "cp /src/%s /vol/%s" % (host_base, zip_name),
            timeout=30)

        if code != 0:
            self._run("rm", "-f", src_ctr, timeout=5, hide=True)
            return False
        else:
            self._run("rm", "-f", src_ctr, timeout=5, hide=True)

        cli_ctr = "wpcli_%s" % uuid.uuid4().hex[:6]
        self._run("rm", "-f", cli_ctr, timeout=5, hide=True)

        theme_dir = "%s" % dest_dir

        code, out, err = self._run(
            "run", "--rm",
            "-v", self.volume + ":/var/www/html:rw",
            "--network", self.net,
            "-e", "WORDPRESS_DB_HOST=" + self.mysql + ":3306",
            "-e", "WORDPRESS_DB_USER=wpuser",
            "-e", "WORDPRESS_DB_PASSWORD=wppass",
            "-e", "WORDPRESS_DB_NAME=testdb",
            "--name", cli_ctr,
            "wordpress:cli",
            "wp", "theme", "install",
            "/var/www/html/wp-content/themes/%s" % zip_name,
            "--force", "--activate", "--allow-root",
            timeout=120)

        if code != 0:
            print("    wp theme install failed:")
            if self.verbose:
                for line in (out + "\n" + err).split("\n")[:40]:
                    if line:
                        print("      " + line)
            return False
        return True

    def teardown(self):
        """Remove containers, network and volume."""
        for name in [self.wp, self.mysql]:
            if name:
                cli("rm", "-f", name, timeout=20, hide=True)
        if self.net:
            cli("network", "rm", self.net, timeout=10, hide=True)
        if self.volume:
            cli("volume", "rm", "-f", self.volume, timeout=10, hide=True)

    def url(self):
        return "http://localhost:%d" % self.port


# ====================== nuclei runner ======================

def run_nuclei(nuclei_path, url, yaml_file, timeout=120, cookie=None, headers=None):
    """Run nuclei CLI. Return (matched, data)."""
    cmd = [nuclei_path, "-u", url, "-t", yaml_file,
           "-jsonl", "-timeout", str(timeout), "-silent"]

    if cookie:
        cmd.extend(["-H", "Cookie: %s" % cookie])
    if headers:
        for h in headers:
            cmd.extend(["-H", h])

    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 30)
    except subprocess.TimeoutExpired:
        return False, {"error": "timed out"}
    except FileNotFoundError:
        return False, {"error": "nuclei not found: " + nuclei_path}

    if res.returncode != 0:
        return False, {"error": "nuclei exited %d: %s" % (res.returncode, res.stderr.strip()[:500])}

    events = []
    for line in res.stdout.strip().splitlines():
        line = line.strip()
        if line and line.startswith("{"):
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                pass

    if events:
        sevs = [e.get("info", {}).get("severity", "?") for e in events]
        return True, {
            "count": len(events),
            "events": events,
            "summary": "%d match(es): %d x critical, %d x high, %d x medium" % (
                len(events),
                sevs.count("critical"),
                sevs.count("high"),
                sevs.count("medium"),
            ),
        }
    return False, {"count": 0, "events": [], "summary": "No matches"}


# ====================== download from WP.org ======================

def download_plugin_zip(slug, version):
    """Download a WP.org plugin ZIP. Returns local path or None."""
    import urllib.request as _urq
    url = "https://downloads.wordpress.org/plugin/%s.%s.zip" % (slug, version)
    tmpdir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "wpnf_tmp")
    os.makedirs(tmpdir, exist_ok=True)
    local = os.path.join(tmpdir, "wpnf_%s_%s.zip" % (slug, version))
    try:
        _urq.urlretrieve(url, local)
        return local
    except Exception:
        return None


# ====================== version helpers ======================

def strip_version(ver_str):
    """Strip comparison operators from version string."""
    import re as _r
    m = _r.search(r"<=?\s*([0-9]+(?:\.[0-9]+)*)", ver_str)
    if m:
        return m.group(1)
    m2 = _r.search(r"([0-9]+(?:\.[0-9]+)*)", ver_str)
    if m2:
        return m2.group(1)
    return ver_str


# ====================== test runner ======================

def test_single_simple(yaml_meta, nuclei_path, verbose=False):
    """Minimal pipeline: Docker -> install -> scan -> clean."""
    slug = yaml_meta["slug"]
    rule_id = yaml_meta["rule_id"]
    vuln_ver = yaml_meta.get("vulnerable_version", "")
    yaml_path = yaml_meta["yaml_path"]

    if verbose:
        print("\n  Rule ID:  %s" % rule_id)
        print("  Slug:     %s" % slug)
        print("  Severity: %s" % yaml_meta.get("severity", "?"))
        print("  Vuln ver: %s" % vuln_ver)
        print("  YAML:     %s" % yaml_path)

    # Parse YAML again for latest version
    rule = parse_simple_yaml(yaml_path)
    if not rule:
        return "failed", "could not parse YAML"

    slug = rule["slug"]
    if verbose:
        print("  Slug:     %s" % slug)

    # Strip comparison operators from version strings
    vuln_ver = strip_version(vuln_ver)
    if not vuln_ver:
        print("\n  X Cannot determine vulnerable version")
        return "rejected", "no version info"

    print("\n  Downloading %s v%s ..." % (slug, vuln_ver))
    vuln_zip = download_plugin_zip(slug, vuln_ver)

    # Check version exists
    if not vuln_zip or not os.path.exists(vuln_zip):
        print("  X Plugin not found on WP.org (v%s)" % vuln_ver)
        return "rejected", "version %s not found" % vuln_ver

    fsize = os.path.getsize(vuln_zip)
    print("  Downloaded OK (%d bytes)" % fsize)

    # Get patched version
    patch_ver = rule.get("patched_version", "")
    if patch_ver:
        import re as _r
        pm = _r.search(r"([0-9]+(?:\.[0-9]+)*)", patch_ver)
        if pm:
            patch_ver = pm.group(1)
        else:
            patch_ver = ""

    # Spin up Docker env
    print("\n  Starting Docker environment ...")
    try:
        env = DockerEnv(verbose=verbose)
        if not env.start():
            return "failed", "Docker env failed"
    except Exception as e:
        return "failed", str(e)

    status_text = "http://localhost:%s" % (env.port or "?")
    print("  Environment ready: " + status_text)

    # Install plugin
    print("\n  Installing plugin %s v%s ..." % (slug, vuln_ver))
    if not env.install_plugin(vuln_zip):
        env.teardown()
        return "failed", "plugin install failed"
    print("  Installed OK")

    url = "http://localhost:%d" % env.port

    # Run nuclei
    print("\n  Running Nuclei scan on vulnerable version ...")
    matched, data = run_nuclei(nuclei_path, url, yaml_path, 120, cookie=None)

    # Clean up Docker
    env.teardown()

    if "error" in data:
        print("\n  X Nuclei error: %s" % data["error"])
        return "failed", data["error"]

    if not matched:
        print("\n  X No match on vulnerable version")
        return "rejected", "no match on vulnerable"

    print("\n  MATCHED: %d hit(s)" % data["count"])
    print("  %s" % data["summary"])

    for i, ev in enumerate(data.get("events", [])[:10], 1):
        tmpl = ev.get("template-id", ev.get("template", "-"))
        info = ev.get("info", {})
        name = info.get("name", "-")
        sev = info.get("severity", "-")
        matcher = ev.get("matcher-name", "-")
        print("    %2d. [%7s] %s  matcher=%s" % (i, sev, name[:55], matcher))

    # Test patched version if available
    if patch_ver:
        print("\n  Testing PATCHED version v%s ..." % patch_ver)
        try:
            env2 = DockerEnv(verbose=verbose)
            if env2.start():
                patched_zip = download_plugin_zip(slug, patch_ver)
                if patched_zip and os.path.exists(patched_zip):
                    if env2.install_plugin(patched_zip):
                        print("\n  Running Nuclei scan on PATCHED version ...")
                        pm, pd = run_nuclei(
                            nuclei_path,
                            "http://localhost:%d" % env2.port,
                            yaml_path, 120)
                        env2.teardown()
                        if pm:
                            print("\n  X False positive: matched on patched too!")
                            return "rejected", "false positive: matched on %s" % patch_ver
                        else:
                            print("\n  PATCHED version clean!")
                    else:
                        env2.teardown()
                        return "skipped", "could not install patched version"
                else:
                    print("\n  Patched version %s not available on WP.org" % patch_ver)
                    env2.teardown()
                    return "skipped", "patched version not available"
            else:
                env2.teardown()
        except Exception as e:
            print("\n  Error testing patched: " + str(e))

    return "verified", data["summary"]


# ====================== main ======================

def main():
    ap = argparse.ArgumentParser(
        description="WP-Nuclei Pipeline: Docker + WordPress CLI test runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--yaml-dir", required=True, help="Directory of YAML files")
    ap.add_argument("--nuclei", default="nuclei", help="Nuclei path")
    ap.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    a = ap.parse_args()

    if not os.path.isdir(a.yaml_dir):
        print("  ERROR: directory not found: " + a.yaml_dir)
        sys.exit(1)

    # verify nuclei
    where = shutil.which(a.nuclei)
    if not where and not os.path.exists(a.nuclei):
        print("  ERROR: nuclei not found: " + a.nuclei)
        sys.exit(1)

    # list yaml files
    yaml_files = sorted(
        f for f in os.listdir(a.yaml_dir)
        if f.lower().endswith((".yaml", ".yml"))
    )
    if not yaml_files:
        print("  ERROR: no YAML files in " + a.yaml_dir)
        sys.exit(1)

    print("\n=============================================================")
    print("  WP-Nuclei Test Runner")
    print("=============================================================")
    print("  YAML dir:  %s" % a.yaml_dir)
    print("  Nuclei:    %s" % a.nuclei)
    print("  Files:     %d" % len(yaml_files))
    print("=============================================================")

    if not cli("docker", "info", timeout=5, hide=True)[0]:
        print("  ERROR: Docker is not running")
        sys.exit(1)
    print("  Docker: running OK")

    counts = {"verified": 0, "rejected": 0, "failed": 0, "skipped": 0}

    for i, fname in enumerate(yaml_files, 1):
        fpath = os.path.abspath(os.path.join(a.yaml_dir, fname))
        print("\n-------------------------------------------------------------")
        print("  [%d/%d] %s" % (i, len(yaml_files), fname))

        rule = parse_simple_yaml(fpath)
        if not rule:
            print("  X Could not parse YAML")
            counts["failed"] += 1
            continue

        status, detail = test_single_simple(
            rule, a.nuclei, verbose=a.verbose)

        counts[status] = counts.get(status, 0) + 1
        if a.verbose:
            print("  Result: %s | %s" % (status, detail))

    # summary
    print("\n=============================================================")
    print("  FINAL SUMMARY")
    print("=============================================================")
    total = sum(counts.values())
    for k, v in counts.items():
        symbol = {"verified": "V", "rejected": "X", "failed": "!", "skipped": "~"}.get(k, "?")
        print("    %s %-10s: %d" % (symbol, k, v))
    print("    total: %d" % total)
    print("=============================================================")

    if counts.get("verified", 0) > 0:
        print("\n  Some rules verified successfully!")
    if counts.get("failed", 0) > 0:
        print("\n  %d rule(s) had errors." % counts["failed"])


if __name__ == "__main__":
    main()
