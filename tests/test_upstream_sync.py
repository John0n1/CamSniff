"""Offline contract checks for the review-only upstream intelligence pipeline."""

import importlib.util
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("upstream", ROOT / "scripts/helpers/sync_upstream_intel.py")
upstream = importlib.util.module_from_spec(spec)
spec.loader.exec_module(upstream)
REV = "a" * 40


class UpstreamSyncTests(unittest.TestCase):
    def test_routes_reject_credentials_and_code_like_inputs(self):
        routes, rejected = upstream.routes_from_text(
            "live.sdp\n/live.sdp\nuser=admin&password=letmein\n"
            "admin:password@10.0.0.1/live\n{{BaseURL}}\n" + "x" * 200 + "\n",
            {"source": "test"},
        )
        self.assertEqual([r["value"] for r in routes], ["/live.sdp", "/live.sdp"])
        self.assertEqual(rejected, 4)

    def test_nuclei_requests_never_survive_normalization(self):
        template = """id: dahua-detect
info:
  name: Camera panel
  severity: info
  tags: dahua,detect
  metadata:
    vendor: Dahua
http:
  - raw: ['POST /danger HTTP/1.1']
"""
        result = upstream.nuclei_metadata(template, {"source": "test"})
        self.assertEqual(result["vendor"], "Dahua")
        self.assertNotIn("POST", json.dumps(result))
        with self.assertRaises(ValueError):
            upstream.nuclei_metadata(template.replace("severity: info", "severity: critical"), {})

    def test_build_is_deterministic_and_inactive(self):
        data = {"cameradar": (REV, "live.sdp\nlive.sdp\nuser=admin&password=x\n"),
                "nuclei-dahua-panel": (REV, "id: dahua-detect\ninfo:\n  name: panel\n  severity: info\n  tags: detect\n")}
        output = upstream.build(data)
        self.assertFalse(output["active"])
        self.assertEqual(output["status"], "review_required")
        self.assertEqual(len(output["records"]), 2)
        self.assertEqual(output["rejected_unsafe_routes"], 1)
        self.assertEqual(output, upstream.build(data))

    def test_commit_provenance_cannot_use_branch_or_url(self):
        with self.assertRaises(ValueError):
            upstream.provenance("x", "owner/repo", "path", "main", "MIT")

    def test_snapshot_is_valid_and_never_contains_credentials(self):
        snapshot = json.loads((ROOT / "data/upstream/candidates.json").read_text())
        self.assertFalse(snapshot["active"])
        self.assertEqual(snapshot["schema_version"], 1)
        self.assertTrue(snapshot["records"])
        for record in snapshot["records"]:
            source = snapshot["sources"][record["source"]]
            self.assertRegex(source["commit"], r"^[0-9a-f]{40}$")
            self.assertIn(source["repository"], ("Ullaakut/cameradar", "projectdiscovery/nuclei-templates"))
            if record["kind"] == "rtsp_route":
                self.assertIsNone(upstream.SECRET.search(record["value"]))
                self.assertTrue(upstream.ROUTE.fullmatch(record["value"]))


if __name__ == "__main__":
    unittest.main()
