#!/usr/bin/env python3
"""WP-Nuclei Pipeline — Docker test runner with wp-cli (NO Docker SDK).

Strategy:
  1. Start MySQL + WordPress containers (no volume mount => WP self-installs)
  2. Wait for WP ready
  3. Install wp-cli inside WP container (curl wp-cli.phar)
  4. docker cp plugin ZIP into container
  5. wp plugin install /tmp/plugin.zip --activate
  6. Run nuclei against the target URL
  7. Clean up containers

Usage:
    python wp_nuclei_pipeline.py --yaml-dir ./test_yamls
    python wp_nuclei_pipeline.py --yaml-dir ./nuclei-templates/cve-less/plugins
    python wp_nuclei_pipeline.py --yaml-dir ./test_yamls --yaml ./test_yamls/wp-fastest-cache-sqli.yaml
    python wp_nuclei_pipeline.py --yaml-dir ./test_yamls --verbose
    python wp_nuclei_pipeline.py --yaml-dir ./test_yamls --nuclei "C:/Users/NEMATO~1/go/bin/nuclei.exe"
    python wp_nuclei_pipeline.py --yaml-dir ./test_yamls --url http://localhost:8080

"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
import uuid
from urllib.request import urlretrieve


# ================================================================
#  Helpers
# ================================================================

def _cli(*args, timeout=60, hide=False):
    """Run a docker CLI command."""
    cmd = ["docker", *args]
    if not hide:
        print("  > docker %s" % " ".join(args))
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired:
        return 1, "", "timeout (%d s)" % timeout
    except Exception as e:
        return 1, "", str(e)


def _random_name(prefix="wpnf"):
    return "%s_%s" % (prefix, uuid.uuid4().hex[:8])


# ================================================================
#  YAML Parser
# ================================================================

def parse_yaml(path):
    """Extract slug, versions, rule_id, severity from a nuclei YAML."""
    import yaml as _yaml
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = _yaml.safe_load(f)
    except Exception:
        return None
    if not data or not isinstance(data, dict):
        return None

    rule_id = data.get("id", "unknown")
    if isinstance(rule_id, dict):
        rule_id = rule_id.get("id", "unknown")
    rule_id = str(rule_id).replace(" ", "_")

    info = data.get("info", {}) or {}
    if not isinstance(info, dict):
        info = {}
    name = str(info.get("name", ""))
    severity = str(info.get("severity", ""))

    # Slug extraction chain
    meta = info.get("metadata", {}) or {}
    if not isinstance(meta, dict):
        meta = {}
    slug = str(meta.get("slug", "")) or str(meta.get("plugin", ""))
    if not slug:
        for k in ("slug", "plugin", "target_slug", "wp_slug"):
            slug = data.get("variables", {}).get(k, "")
            if slug:
                break
    if not slug:
        tags = info.get("tags", "")
        if tags:
            if isinstance(tags, str):
                tags = [t.strip() for t in tags.split(",")]
            skip = {"cve", "wordpress", "wp-plugin", "wp-theme", "production",
                    "medium", "low", "high", "critical", "info", "local", "network",
                    "manual", "panel", "default-logins", "misconfig", "exposure",
                    "iot", "mask", "tech", "microsoft", "jira", "grafana", "tomcat",
                    "jenkins", "wordpress-core", "wordpress-themes", "wordpress-plugins",
                    "rce", "sqli", "xss", "csrf", "lfi", "rfi", "ssrf", "dos",
                    "unauth", "auth", "sensitive", "default"}
            for t in tags:
                t = t.strip().lower()
                if t and t not in skip:
                    slug = t
                    break
    if not slug:
        words = name.split()
        if words:
            slug = "-".join(w.lower() for w in words)
    if not slug:
        basename = os.path.basename(path)
        slug = basename.split("-")[0]

    # Version extraction
    def extract_ver(*keys):
        for k in keys:
            v = data.get("info", {}).get("metadata", {}).get(k, "") or data.get("variables", {}).get(k, "")
            if v:
                return str(v)
        return ""

    vuln_ver = extract_ver("vulnerable_version", "vuln_version", "affected_version", "vulnerable")
    patch_ver = extract_ver("patched_version", "safe_version", "fixed_version")

    return {
        "rule_id": rule_id,
        "name": name,
        "severity": severity,
        "slug": slug,
        "vulnerable_version": vuln_ver,
        "patched_version": patch_ver,
        "yaml_path": os.path.abspath(path),
    }


# ================================================================
#  Docker Environment (CLI-based, NO SDK, NO volume mount)
# ================================================================

class DockerEnv:
    """Isolated WordPress + MySQL via docker CLI.
    
    Key decision: NO -v volume mount.
    Reason: WordPress self-initializes on first run by writing into /var/www/html.
    Mounting a volume to that path breaks initialization.
    
    Instead we use:
    - docker cp to copy plugin zip into the container
    - WP-CLI installed inside the container (curl wp-cli.phar)
    """

    def __init__(self, verbose=False):
        self.prefix = _random_name()
        self.net = "%s_net" % self.prefix
        self.mysql = "%s_db" % self.prefix
        self.wp = "%s_wp" % self.prefix
        self.port = None
        self.verbose = verbose

    def __enter__(self):
        if not self.start():
            raise RuntimeError("DockerEnv start failed")
        return self

    def __exit__(self, *e):
        self.teardown()
        return False

    def _run(self, *args, timeout=60):
        return _cli(*args, timeout=timeout, hide=not self.verbose)

    # ---- setup ----
    def start(self):
        self.teardown()  # clean old leftovers

        if self.verbose:
            print("  Prefix: %s" % self.prefix)

        # 1. Network
        code, _, err = self._run("network", "create", self.net, timeout=10)
        if code:
            print("  ERROR: network create: " + err)
            return False

        # 2. MySQL
        code, _, err = self._run(
            "run", "-d", "--name", self.mysql,
            "-e", "MYSQL_ROOT_PASSWORD=rootpass",
            "-e", "MYSQL_DATABASE=testdb",
            "-e", "MYSQL_USER=wpuser", "-e", "MYSQL_PASSWORD=wppass",
            "--network", self.net,
            "mysql:8.0",
            timeout=30)
        if code:
            print("  ERROR: MySQL: " + err)
            self._run("network", "rm", self.net, timeout=5, hide=True)
            return False
        if self.verbose:
            print("  MySQL started")

        # 3. WordPress — NO volume mount
        code, _, err = self._run(
            "run", "-d", "-p", "0:80",
            "--name", self.wp,
            "-e", "WORDPRESS_DB_HOST=" + self.mysql + ":3306",
            "-e", "WORDPRESS_DB_USER=wpuser",
            "-e", "WORDPRESS_DB_PASSWORD=wppass",
            "-e", "WORDPRESS_DB_NAME=testdb",
            "--network", self.net,
            "wordpress:latest",
            timeout=30)
        if code:
            print("  ERROR: WP: " + err)
            self.teardown()
            return False
        if self.verbose:
            print("  WP started")

        # 4. Discover host port
        code, out, _ = self._run("inspect", "-f",
            "{{(index .NetworkSettings.Ports \"80/tcp\") 0 .HostPort}}",
            self.wp)
        # Fallback: parse from regular inspect output
        if code or not out:
            code, out2, _ = self._run("port", self.wp, "80")
            import re as _re
            m = _re.search(r"0\.0\.0\.0:(\d+)", out2)
            if m:
                self.port = int(m.group(1))
            else:
                print("  ERROR: cannot find WP port")
                self.teardown()
                return False
        else:
            self.port = int(out)

        # 5. Wait for WP ready (first-run install can take a while)
        if self.verbose:
            print("  Waiting for WP (up to 5 min)...")

        for i in range(150):
            code, out, _ = self._run(
                "exec", self.wp, "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                "http://127.0.0.1/")
            if out and out.startswith("2"):
                if self.verbose:
                    print("  WP ready on port %d (after %d retries)" % (self.port, i))
                return True
            time.sleep(2)

        # Print last few attempts for debugging
        if self.verbose:
            print("  Last check result: code=%s out=%s" % (code, out))
        print("  ERROR: WP timed out (5 min)")
        self.teardown()
        return False

    # ---- wp-cli installer ----
    def _install_wpcli(self, force=False):
        """Ensure wp-cli is installed inside the WP container."""
        if self.verbose:
            print("  Ensuring wp-cli ...")
        code, out, _ = self._run("exec", self.wp, "wp", "--info" if force else "--info")
        if not code:
            if self.verbose:
                print("  wp-cli already installed")
            return True

        # Install via curl
        code, out, err = self._run("exec", self.wp, "bash", "-c",
            "curl -sSL https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar "
            "-o /usr/local/bin/wp && chmod +x /usr/local/bin/wp")
        if code:
            # try /wp-cli.phar fallback
            code, out, err = self._run("exec", self.wp, "bash", "-c",
                "cd /var/www/html && curl -sSL https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar "
                "-o /usr/local/bin/wp && chmod +x /usr/local/bin/wp")
        if code:
            print("  WARN: wp-cli install failed: " + (err or str(out))[:200])
            return False
        if self.verbose:
            print("  wp-cli installed")
        return True

    # ---- plugin/theme install via docker cp + wp-cli ----
    def install_plugin(self, zip_path):
        """Copy zip into container, install with wp-cli."""
        if not self._install_wpcli():
            return False

        zip_name = self.prefix + "_plugin.zip"
        dst = "/tmp/%s" % zip_name

        # mkdir -p
        self._run("exec", self.wp, "mkdir", "-p", "/tmp", timeout=5)

        # docker cp
        code, _, err = self._run("cp", os.path.abspath(str(zip_path)),
                                 "%s:%s" % (self.wp, dst), timeout=120)
        if code:
            print("    docker cp failed: " + (err or "")[:200])
            return False

        # wp plugin install
        code, out, err = self._run("exec", self.wp, "wp", "plugin", "install",
            dst, "--activate", "--allow-root", timeout=120)
        if code:
            print("    wp plugin install failed:")
            if self.verbose:
                for line in ((out or "") + "\n" + (err or "")).split("\n")[:30]:
                    if line:
                        print("      " + line)
            self._run("exec", self.wp, "rm", "-f", dst, timeout=5, hide=True)
            return False

        # cleanup
        self._run("exec", self.wp, "rm", "-f", dst, timeout=5, hide=True)

        if self.verbose:
            print("    Plugin installed OK")
        return True

    def install_theme(self, zip_path):
        """Copy zip into container, install theme with wp-cli."""
        if not self._install_wpcli():
            return False

        zip_name = self.prefix + "_theme.zip"
        dst = "/tmp/%s" % zip_name

        code, _, err = self._run("cp", os.path.abspath(str(zip_path)),
                                 "%s:%s" % (self.wp, dst), timeout=120)
        if code:
            print("    docker cp failed: " + (err or "")[:200])
            return False

        code, out, err = self._run("exec", self.wp, "wp", "theme", "install",
            dst, "--activate", "--allow-root", timeout=120)
        if code:
            print("    wp theme install failed:")
            if self.verbose:
                for line in ((out or "") + "\n" + (err or "")).split("\n")[:30]:
                    if line:
                        print("      " + line)
            return False
        self._run("exec", self.wp, "rm", "-f", dst, timeout=5, hide=True)
        return True

    # ---- teardown ----
    def teardown(self):
        for name in (self.wp, self.mysql):
            if name:
                _cli("rm", "-f", name, timeout=20, hide=True)
        if self.net:
            _cli("network", "rm", self.net, timeout=10, hide=True)

    def url(self):
        return "http://localhost:%d" % self.port


# ================================================================
#  Nuclei Runner
# ================================================================

def run_nuclei(ncli, url, tmpl, timeout=120, cookie=None, headers=None):
    """Run nuclei CLI on a single target. Returns (matched:bool, data:dict)."""
    cmd = [ncli, "-u", url, "-t", tmpl,
           "-jsonl", "-timeout", str(timeout), "-silent"]
    if cookie:
        cmd.extend(["-H", "Cookie: %s" % cookie])
    if headers:
        for h in headers:
            cmd.extend(["-H", h])

    try:
        res = subprocess.run(cmd, capture_output=True, text=True,
                            timeout=timeout + 30)
    except subprocess.TimeoutExpired:
        return False, {"error": "timed out (%d s)" % timeout}
    except FileNotFoundError:
        return False, {"error": "nuclei not found: " + ncli}

    if res.returncode != 0:
        return False, {"error": "nuclei exited %d: %s" % (res.returncode, res.stderr.strip()[:500])}

    events = []
    for line in (res.stdout or "").strip().splitlines():
        line = line.strip()
        if line and line.startswith("{"):
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                pass

    if events:
        sevs = [e.get("info", {}).get("severity", "?") for e in events]
        summary = "%d match(es): %d x critical, %d x high, %d x medium" % (
            len(events),
            sevs.count("critical"),
            sevs.count("high"),
            sevs.count("medium"),
        )
        return True, {"count": len(events), "events": events, "summary": summary}
    return False, {"count": 0, "events": [], "summary": "No matches"}


# ================================================================
#  Version helpers
# ================================================================

_V_RE = re.compile(r"<=?\s*([0-9]+(?:\.[0-9]+)*)")

def strip_ver(raw):
    """Extract bare version number from '<= 1.2.3' => '1.2.3'."""
    m = _V_RE.search(str(raw))
    return m.group(1) if m else str(raw)


# ================================================================
#  Download from WP.org
# ================================================================

def wp_download(slug, version):
    """Download WordPress plugin ZIP. Returns local path or None."""
    url = "https://downloads.wordpress.org/plugin/%s.%s.zip" % (slug, version)
    tmpdir = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".wpnf_tmp")
    os.makedirs(tmpdir, exist_ok=True)
    local = os.path.join(tmpdir, "%s.%s.zip" % (slug, version))
    if os.path.exists(local):
        return local
    try:
        urlretrieve(url, local)
        return local
    except Exception:
        return None


# ================================================================
#  Test pipeline (single rule)
# ================================================================

def test_rule(rule_meta, ncli, verbose=False):
    """Full pipeline: download => Docker => plugin => scan => clean."""
    slug = rule_meta["slug"]
    rule_id = rule_meta["rule_id"]
    vuln_ver = rule_meta.get("vulnerable_version", "")
    patch_ver = rule_meta.get("patched_version", "")
    yaml_path = rule_meta["yaml_path"]

    # Resolve YAML
    rule = parse_yaml(yaml_path)
    if not rule:
        return "failed", "parse error"
    slug = rule["slug"]

    # Strip version comparison operators
    vuln_ver = strip_ver(vuln_ver)
    if not vuln_ver:
        return "rejected", "no vulnerable version"
    if patch_ver:
        patch_ver = strip_ver(patch_ver)

    # Debug info
    if verbose:
        print("\n  ID:      %s" % rule_id)
        print("  Slug:    %s" % slug)
        print("  Severity:%s" % rule["severity"])
        print("  Vuln ver:%s" % vuln_ver)
        print("  Patch ver:%s" % patch_ver)
        print("  YAML:    %s" % yaml_path)

    # 1 Download vulnerable version
    print("\n  [1/5] Download %s v%s ..." % (slug, vuln_ver))
    vuln_zip = wp_download(slug, vuln_ver)
    if not vuln_zip or not os.path.exists(vuln_zip):
        print("  X Not found on WP.org")
        return "rejected", "version not found"
    print("  Downloaded (%d bytes)" % os.path.getsize(vuln_zip))

    # 2. Spin up Docker environment
    print("[2/5] Starting Docker (MySQL + WP)...")
    try:
        env = DockerEnv(verbose=verbose)
        if not env.start():
            return "failed", "Docker failed"
    except Exception as e:
        return "failed", str(e)

    target = env.url()
    print("  Target: %s" % target)

    # 3. Install vulnerable plugin
    print("[3/5] Installing vulnerable plugin...")
    if not env.install_plugin(vuln_zip):
        env.teardown()
        return "failed", "install failed"
    print("  Installed OK")

    # 4. Scan vulnerable version
    print("[4/5] Nuclei scan on vulnerable...")
    matched, data = run_nuclei(ncli, target, yaml_path, timeout=120)
    env.teardown()  # Always clean up

    if "error" in data:
        return "failed", data["error"]

    if not matched:
        print("  X No match — rule may be invalid")
        return "rejected", "no match"

    print("  V MATCH: %d hit(s) %s" % (data["count"], data["summary"]))
    for i, ev in enumerate(data.get("events", [])[:10], 1):
        tmpl = ev.get("template-id", "-")
        info = ev.get("info", {})
        sev = info.get("severity", "?")
        matcher = ev.get("matcher-name", "-")
        print("    %2d. [%7s] %s  matcher=%s" % (i, sev,
                info.get("name", "-")[:50], matcher))

    # 5. Scan patched version (if available)
    if patch_ver:
        print("\n  [5/5] Testing PATCHED version v%s ..." % patch_ver)
        try:
            env2 = DockerEnv(verbose=verbose)
            patch_zip = wp_download(slug, patch_ver)
            if not patch_zip or not os.path.exists(patch_zip):
                print("  Patched version not available on WP.org")
                return "skipped", "patched not available"
            if env2.start():
                if env2.install_plugin(patch_zip):
                    matched2, data2 = run_nuclei(ncli, env2.url(), yaml_path, 120)
                    env2.teardown()
                    if matched2:
                        return "rejected", "FALSE POSITIVE — also matches patched"
                    print("  PATCHED clean (no match)")
                else:
                    env2.teardown()
                    return "skipped", "install patched failed"
            else:
                env2.teardown()
                return "skipped", "Docker failed for patched"
        except Exception as e:
            print("  Error testing patched: " + str(e))

    return "verified", data.get("summary", "matched")


# ================================================================
#  Main
# ================================================================

def main():
    ap = argparse.ArgumentParser(
        description="WP-Nuclei Pipeline — docker CLI test runner (no SDK)",
        epilog="""
Examples:
  python wp_nuclei_pipeline.py --yaml-dir ./test_yamls
  python wp_nuclei_pipeline.py --yaml-dir ./nuclei-templates/cve-less/plugins
  python wp_nuclei_pipeline.py --yaml-dir ./test_yamls --yaml ./test_yamls/wp-fastest-cache-sqli.yaml
  python wp_nuclei_pipeline.py --yaml-dir ./test_yamls --verbose
  python wp_nuclei_pipeline.py --yaml-dir ./test_yamls --nuclei "C:/Users/NEMATO~1/go/bin/nuclei.exe"

""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--yaml-dir",  help="Directory of YAML files")
    ap.add_argument("--yaml", "-f", help="Single YAML file (overrides --yaml-dir)")
    ap.add_argument("--nuclei", default="nuclei", help="Nuclei path")
    ap.add_argument("--verbose", "-v", action="store_true")
    a = ap.parse_args()

    if not a.yaml_dir and not a.yaml:
        print("ERROR: need --yaml-dir or --yaml")
        sys.exit(1)
    if a.yaml_dir and a.yaml:
        print("ERROR: use one of --yaml-dir or --yaml")
        sys.exit(1)

    # Resolve YAML sources
    if a.yaml_dir:
        yaml_sources = sorted(
            os.path.join(a.yaml_dir, f)
            for f in os.listdir(a.yaml_dir)
            if f.lower().endswith((".yaml", ".yml")))
    else:
        yaml_sources = [os.path.abspath(a.yaml)]

    if not yaml_sources:
        print("ERROR: no YAML files found")
        sys.exit(1)

    # Check nuclei
    if not shutil.which(a.nuclei) and not os.path.exists(a.nuclei):
        print("ERROR: nuclei not found: " + a.nuclei)
        sys.exit(1)

    # Check Docker
    code, _, _ = _cli("info", timeout=5, hide=True)
    if code:
        print("ERROR: Docker is not running")
        sys.exit(1)

    # Header
    print("\n" + "=" * 65)
    print("  WP-Nuclei Pipeline")
    print("=" * 65)
    print("  Nuclei: %s" % a.nuclei)
    print("  Files:  %d" % len(yaml_sources))
    print("=" * 65)

    results = {"verified": 0, "rejected": 0, "failed": 0, "skipped": 0}

    for i, yf in enumerate(yaml_sources, 1):
        print("\n" + "-" * 65)
        print("  [%d/%d] %s" % (i, len(yaml_sources), os.path.basename(yf)))

        rule = parse_yaml(yf)
        if not rule:
            print("  X Cannot parse")
            results["failed"] += 1
            continue

        status, detail = test_rule(rule, a.nuclei, verbose=a.verbose)
        results[status] = results.get(status, 0) + 1
        if a.verbose:
            print("  => %s: %s" % (status, detail))

    # Summary
    print("\n" + "=" * 65)
    print("  SUMMARY")
    print("=" * 65)
    for k in ("verified", "rejected", "failed", "skipped"):
        if results[k]:
            sym = {"verified": "V", "rejected": "X", "failed": "!", "skipped": "~"}[k]
            print("  %s %-10s: %d" % (sym, k, results[k]))
    print("  total: %d" % sum(results.values()))
    print("=" * 65)


if __name__ == "__main__":
    main()
