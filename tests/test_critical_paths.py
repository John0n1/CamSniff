from __future__ import annotations

import importlib.util
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import types
import unittest
import xml.etree.ElementTree
from datetime import UTC, datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "helpers"))
sys.path.insert(0, str(ROOT / "scripts" / "tools"))

import confidence_scorer  # noqa: E402
import profile_resolver  # noqa: E402
import report  # noqa: E402


class ReleaseMetadataTests(unittest.TestCase):
    def test_release_versions_stay_in_sync(self) -> None:
        version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
        self.assertRegex(version, r"^\d+\.\d+\.\d+$")

        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        manual = (ROOT / "docs" / "camsniff.1").read_text(encoding="utf-8")
        pkgbuild = (ROOT / "packaging" / "arch" / "PKGBUILD").read_text(
            encoding="utf-8"
        )
        debian_changelog = (ROOT / "debian" / "changelog").read_text(
            encoding="utf-8"
        )

        self.assertIn(f"**Version {version}**", readme)
        self.assertIn(f"CamSniff {version}", manual)
        self.assertRegex(pkgbuild, rf"(?m)^pkgver={re.escape(version)}$")
        self.assertTrue(debian_changelog.startswith(f"camsniff ({version}) "))


def load_ivre_sync():
    path = ROOT / "scripts" / "integrations" / "ivre-sync.py"
    spec = importlib.util.spec_from_file_location("ivre_sync", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_ssdp_probe():
    if "defusedxml.ElementTree" not in sys.modules:
        package = types.ModuleType("defusedxml")
        package.ElementTree = xml.etree.ElementTree
        sys.modules.setdefault("defusedxml", package)
        sys.modules.setdefault("defusedxml.ElementTree", xml.etree.ElementTree)
    path = ROOT / "scripts" / "probes" / "ssdp_probe.py"
    spec = importlib.util.spec_from_file_location("ssdp_probe", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ProfileAndConfidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        catalog = profile_resolver._load_catalog(ROOT / "data" / "catalog" / "paths.csv")
        cls.resolver = profile_resolver.ProfileResolver(catalog)

    def test_common_port_alone_does_not_claim_a_vendor(self) -> None:
        host = profile_resolver.HostContext(ip="10.0.0.10", ports=[554])
        self.assertEqual(self.resolver.resolve_many(host), [])

    def test_oui_remains_strong_vendor_evidence(self) -> None:
        host = profile_resolver.HostContext(
            ip="10.0.0.10", mac="AC:CC:8E:00:00:01", ports=[554]
        )
        matches = self.resolver.resolve_many(host, limit=1)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0][1], "oui")
        self.assertGreaterEqual(matches[0][2], 100)

    def test_evidence_free_host_is_not_classified_as_camera(self) -> None:
        result = confidence_scorer.score_host(
            {"ip": "10.0.0.20", "sources": [], "ports": []}
        )
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["classification"], "unknown")


class IntegrationContractTests(unittest.TestCase):
    def test_scan_summaries_ignore_command_flags(self) -> None:
        nmap_output = """# Nmap scan initiated as: nmap --open -p 80 127.0.0.1
# Nmap done -- 1 IP address (1 host up) scanned
"""
        masscan_output = [
            {"ip": "10.0.0.1", "ports": [{"port": 80}, {"port": 554}]},
            {"ip": "10.0.0.1", "ports": [{"port": 8080}]},
            {"ip": "10.0.0.2", "ports": [{"port": 443}]},
        ]
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            nmap_path = temp / "nmap.txt"
            masscan_path = temp / "masscan.json"
            nmap_path.write_text(nmap_output, encoding="utf-8")
            masscan_path.write_text(json.dumps(masscan_output), encoding="utf-8")
            helper = ROOT / "scripts" / "core" / "scan_summary.sh"
            script = (
                f'source "{helper}"; '
                f'nmap_hosts_up_count "{nmap_path}"; echo; '
                f'nmap_open_port_count "{nmap_path}"; '
                f'masscan_host_count "{masscan_path}"; '
                f'masscan_open_port_count "{masscan_path}"'
            )
            proc = subprocess.run(
                ["bash", "-c", script], text=True, capture_output=True, check=True
            )
        self.assertEqual(proc.stdout.splitlines(), ["1", "0", "2", "4"])

    def test_tshark_parser_preserves_quoted_commas_and_empty_fields(self) -> None:
        row = (
            '"0.25","192.168.1.20","192.168.1.40","51000","80",'
            '"","","camera.local","/snapshot.jpg?x=1,y=2",""\n'
        )
        with tempfile.NamedTemporaryFile("w", suffix=".csv") as handle:
            handle.write(row)
            handle.flush()
            proc = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "helpers" / "tshark_event_parser.py"),
                    "--input",
                    handle.name,
                ],
                text=True,
                capture_output=True,
                check=True,
            )
        fields = proc.stdout.rstrip("\n").split("\x1f")
        self.assertEqual(len(fields), 10)
        self.assertEqual(fields[4], "80")
        self.assertEqual(fields[8], "/snapshot.jpg?x=1,y=2")

    def test_reports_redact_url_credentials(self) -> None:
        self.assertEqual(
            report.redact_url_credentials("rtsp://admin:secret@10.0.0.5/live"),
            "rtsp://[redacted]@10.0.0.5/live",
        )

    def test_ssdp_descriptions_cannot_leave_scan_scope(self) -> None:
        module = load_ssdp_probe()
        networks = module._allowed_networks(["192.168.50.0/24"])
        self.assertTrue(
            module._url_is_in_scope("http://192.168.50.12/device.xml", networks)
        )
        self.assertFalse(
            module._url_is_in_scope("http://169.254.169.254/latest/meta-data", networks)
        )
        self.assertFalse(
            module._url_is_in_scope("https://203.0.113.10/device.xml", networks)
        )

    def test_scope_helper_rejects_addresses_outside_declared_targets(self) -> None:
        script = (
            f'source "{ROOT / "scripts" / "core" / "scope.sh"}"; '
            'scan_targets=("192.168.10.0/24" "10.0.0.8"); '
            "is_authorized_ip 192.168.10.44; "
            "! is_authorized_ip 192.168.11.44; "
            "is_authorized_ip 10.0.0.8; "
            "! is_authorized_ip 10.0.0.9"
        )
        subprocess.run(["bash", "-c", script], check=True)

    def test_ivre_reads_nested_success_credentials(self) -> None:
        module = load_ivre_sync()
        payload = [
            {
                "ip": "10.0.0.30",
                "success": True,
                "method": "http_snapshot",
                "credentials": {"username": "admin", "password": "secret"},
                "artifact": {"snapshot": "/tmp/camera.jpg"},
                "url": "http://10.0.0.30/snapshot.jpg",
            }
        ]
        with tempfile.NamedTemporaryFile("w", suffix=".json") as handle:
            json.dump(payload, handle)
            handle.flush()
            parsed = module.load_credentials(Path(handle.name))["10.0.0.30"]
        self.assertTrue(parsed["success"])
        self.assertEqual(parsed["username"], "admin")
        self.assertEqual(parsed["password"], "secret")
        self.assertEqual(parsed["thumbnail"], "/tmp/camera.jpg")

    def test_ivre_preserves_tcp_and_udp_service_types(self) -> None:
        module = load_ivre_sync()
        ivre_package = types.ModuleType("ivre")
        ivre_package.xmlnmap = types.SimpleNamespace(SCHEMA_VERSION=1)
        sys.modules["ivre"] = ivre_package
        documents = module.build_host_documents(
            {
                "hosts": [
                    {
                        "ip": "10.0.0.31",
                        "services": [
                            {"protocol": "tcp", "port": 554, "state": "open"},
                            {
                                "protocol": "udp",
                                "port": 3702,
                                "state": "open_filtered",
                            },
                        ],
                    }
                ]
            },
            mode="medium",
            network="10.0.0.0/24",
            run_dir="/tmp/run",
            timestamp=datetime.now(UTC),
            vendor_db={},
            creds_db={},
        )
        services = {
            (entry["protocol"], entry["port"], entry["state_state"])
            for entry in documents[0]["ports"]
            if entry["port"] > 0
        }
        self.assertIn(("tcp", 554, "open"), services)
        self.assertIn(("udp", 3702, "open|filtered"), services)

    def test_masscan_json_contract_keeps_all_ports(self) -> None:
        payload = [
            {
                "ip": "10.0.0.40",
                "ports": [{"port": 80}, {"port": 554}],
            }
        ]
        query = '.[]? | .ip as $ip | .ports[]? | [$ip, (.port | tostring)] | @tsv'
        proc = subprocess.run(
            ["jq", "-r", query],
            input=json.dumps(payload),
            text=True,
            capture_output=True,
            check=True,
        )
        self.assertEqual(
            proc.stdout.splitlines(), ["10.0.0.40\t80", "10.0.0.40\t554"]
        )


class CredentialProbeTests(unittest.TestCase):
    def test_rtsp_userinfo_is_url_encoded(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            fake_bin = temp / "bin"
            fake_bin.mkdir()
            fake_ffmpeg = fake_bin / "ffmpeg"
            fake_ffmpeg.write_text(
                "#!/usr/bin/env bash\n"
                "printf '%s\\n' \"$*\" >> \"$CAM_TEST_CALLS\"\n"
                "out=\"${@: -1}\"\n"
                "python3 -c 'import pathlib, sys; pathlib.Path(sys.argv[1]).write_bytes(bytes(2048))' \"$out\"\n",
                encoding="utf-8",
            )
            fake_ffmpeg.chmod(fake_ffmpeg.stat().st_mode | stat.S_IXUSR)

            discovery = temp / "discovery.json"
            discovery.write_text(
                json.dumps(
                    {
                        "hosts": [
                            {
                                "ip": "127.0.0.1",
                                "confidence": {"score": 100},
                                "profile_match": {
                                    "vendor": "Test",
                                    "model": "Test",
                                    "default_username": "admin@site",
                                    "default_password": "p:a/ss",
                                    "rtsp_candidates": [
                                        {
                                            "template": "rtsp://{{username}}:{{password}}@{{ip_address}}:{{port}}/live",
                                            "port": 554,
                                        }
                                    ],
                                },
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            empty_http_paths = temp / "http-paths.txt"
            empty_http_paths.write_text("", encoding="utf-8")
            output = temp / "credentials.json"
            env = os.environ.copy()
            env["PATH"] = f"{fake_bin}:{env['PATH']}"
            env["CAM_TEST_CALLS"] = str(temp / "ffmpeg-calls")

            proc = subprocess.run(
                [
                    "bash",
                    str(ROOT / "scripts" / "probes" / "credential-probe.sh"),
                    "--input",
                    str(discovery),
                    "--mode",
                    "stealth+",
                    "--http-paths",
                    str(empty_http_paths),
                    "--output",
                    str(output),
                    "--thumbnails",
                    str(temp / "thumbnails"),
                    "--log-dir",
                    str(temp / "logs"),
                ],
                env=env,
                capture_output=True,
                text=True,
                check=True,
            )

            result = json.loads(output.read_text(encoding="utf-8"))[0]
            calls_file = temp / "ffmpeg-calls"
            calls = calls_file.read_text(encoding="utf-8") if calls_file.exists() else ""
            logs = "\n".join(
                path.read_text(encoding="utf-8", errors="replace")
                for path in (temp / "logs").glob("*.log")
            )
            self.assertTrue(
                result["success"],
                msg=f"stdout={proc.stdout!r} stderr={proc.stderr!r} calls={calls!r} logs={logs!r}",
            )
            self.assertIn("admin%40site:p%3Aa%2Fss@127.0.0.1", result["url"])
            self.assertEqual(result["credentials"]["password"], "p:a/ss")

    def test_per_host_probe_window_is_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            fake_bin = temp / "bin"
            fake_bin.mkdir()
            calls = temp / "curl-calls"
            fake_curl = fake_bin / "curl"
            fake_curl.write_text(
                "#!/usr/bin/env bash\n"
                "printf 'called\\n' >> \"$CAM_TEST_CALLS\"\n"
                "printf '401'\n",
                encoding="utf-8",
            )
            fake_curl.chmod(fake_curl.stat().st_mode | stat.S_IXUSR)

            discovery = temp / "discovery.json"
            discovery.write_text(
                json.dumps(
                    {"hosts": [{"ip": "127.0.0.1", "confidence": {"score": 0}}]}
                ),
                encoding="utf-8",
            )
            http_paths = temp / "http-paths.txt"
            http_paths.write_text(
                "http://{{ip_address}}/snapshot.jpg|80|1|0|test\n",
                encoding="utf-8",
            )
            output = temp / "credentials.json"
            env = os.environ.copy()
            env["PATH"] = f"{fake_bin}:{env['PATH']}"
            env["CAM_TEST_CALLS"] = str(calls)
            env["CAM_SNIFF_BRUTE_WINDOW"] = "0"

            subprocess.run(
                [
                    "bash",
                    str(ROOT / "scripts" / "probes" / "credential-probe.sh"),
                    "--input",
                    str(discovery),
                    "--mode",
                    "stealth+",
                    "--http-paths",
                    str(http_paths),
                    "--output",
                    str(output),
                    "--thumbnails",
                    str(temp / "thumbnails"),
                    "--log-dir",
                    str(temp / "logs"),
                ],
                env=env,
                capture_output=True,
                text=True,
                check=True,
            )

            self.assertFalse(calls.exists())
            result = json.loads(output.read_text(encoding="utf-8"))[0]
            self.assertTrue(result["budget_exhausted"])
            self.assertEqual(result["attempts"], 0)

    def test_each_credential_gets_its_own_http_attempt(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            fake_bin = temp / "bin"
            fake_bin.mkdir()
            calls = temp / "curl-calls"
            fake_curl = fake_bin / "curl"
            fake_curl.write_text(
                "#!/usr/bin/env bash\n"
                "printf '%s\\n' \"$*\" >> \"$CAM_TEST_CALLS\"\n"
                "printf '401'\n",
                encoding="utf-8",
            )
            fake_curl.chmod(fake_curl.stat().st_mode | stat.S_IXUSR)

            discovery = temp / "discovery.json"
            discovery.write_text(
                json.dumps({"hosts": [{"ip": "127.0.0.1", "confidence": {"score": 0}}]}),
                encoding="utf-8",
            )
            http_paths = temp / "http-paths.txt"
            http_paths.write_text(
                "http://{{ip_address}}/snapshot.jpg|80|1|0|test\n",
                encoding="utf-8",
            )

            env = os.environ.copy()
            env["PATH"] = f"{fake_bin}:{env['PATH']}"
            env["CAM_TEST_CALLS"] = str(calls)
            subprocess.run(
                [
                    "bash",
                    str(ROOT / "scripts" / "probes" / "credential-probe.sh"),
                    "--input",
                    str(discovery),
                    "--mode",
                    "stealth+",
                    "--http-paths",
                    str(http_paths),
                    "--output",
                    str(temp / "credentials.json"),
                    "--thumbnails",
                    str(temp / "thumbnails"),
                    "--log-dir",
                    str(temp / "logs"),
                ],
                env=env,
                capture_output=True,
                text=True,
                check=True,
            )
            # Generic HTTP probing is intentionally capped at six credential pairs.
            call_lines = calls.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(call_lines), 6)
            self.assertTrue(any("--user" in line for line in call_lines[1:]))
            self.assertTrue(all("@127.0.0.1" not in line for line in call_lines))
            self.assertEqual(list((temp / "thumbnails").glob("*.jpg")), [])


if __name__ == "__main__":
    unittest.main()
