"""Run with python3 -m unittest discover -s tests -v; no network required."""

import ast
import html
import re
import ssl
import typing
import unittest
import urllib.error
import urllib.request
from email.message import Message
from pathlib import Path
from unittest.mock import MagicMock, patch

SCRIPT = Path(__file__).resolve().parents[1] / "connectivity-test-zone.sh"
SOURCE = (
    SCRIPT.read_text()
    .split('python3 - "$SUBS"', 1)[1]
    .split("<<'PY'\n", 1)[1]
    .rsplit("\nPY", 1)[0]
)
FUNCTIONS = {
    "assess_php_cve_exposure",
    "fetch_http_endpoint",
    "selected_header_values",
    "extract_title",
}
TREE = ast.parse(SOURCE)
MODULE = ast.Module(
    body=[
        node
        for node in TREE.body
        if isinstance(node, ast.FunctionDef) and node.name in FUNCTIONS
    ],
    type_ignores=[],
)


class PHPExposureTests(unittest.TestCase):
    def setUp(self):
        self.hints = []
        self.existing = {
            "title": "Existing header finding",
            "severity_hint": "low",
            "evidence": {},
        }
        self.ns = {
            **vars(typing),
            "re": re,
            "ssl": ssl,
            "urllib": urllib,
            "html": html,
            "SECURITY_HEADER_SCORE_KEYS": [],
            "HTTP_BODY_LIMIT_BYTES": 4096,
            "http_timeout_seconds": 1,
            "assess_security_headers": lambda *args: ({}, {}, [self.existing]),
            "append_hint": lambda **kw: self.hints.append(kw),
        }
        exec(compile(MODULE, str(SCRIPT), "exec"), self.ns)  # noqa: S102 - local embedded functions

    def assess(self, version):
        return self.ns["assess_php_cve_exposure"]({"x-powered-by": f"PHP/{version}"})

    def test_supported_branch_boundaries(self):
        for minor, fixed in ((2, 35), (3, 36), (4, 27), (5, 12)):
            with self.subTest(minor=minor):
                findings = self.assess(f"8.{minor}.{fixed - 1}")
                self.assertEqual(
                    {f["cve"] for f in findings}, {"CVE-2026-109618", "CVE-2026-109619"}
                )
                self.assertTrue(
                    all(f["assessment"] == "potentially_affected" for f in findings)
                )
                self.assertEqual(findings[0]["fixed_version"], f"8.{minor}.{fixed}")
                self.assertEqual(self.assess(f"8.{minor}.{fixed}"), [])
                self.assertEqual(self.assess(f"8.{minor}.{fixed + 1}"), [])

    def test_legacy_and_vendor_banners_require_validation(self):
        for version in (
            "5.4.45",
            "5.6.40",
            "7.4.33",
            "8.0.30",
            "8.1.34",
            "8.2.34-1ubuntu1",
        ):
            with self.subTest(version=version):
                findings = self.assess(version)
                self.assertEqual(len(findings), 2)
                self.assertIn("backports", findings[0]["validation"])

    def test_missing_incomplete_and_unrecognized_versions(self):
        self.assertEqual(self.ns["assess_php_cve_exposure"]({}), [])
        for version in ("", "8.4", "8.6.0", "9.0.0", "4.4.9", "8.4.26.1"):
            with self.subTest(version=version):
                self.assertEqual(self.assess(version), [])

    def test_server_banner_and_duplicate_evidence(self):
        findings = self.ns["assess_php_cve_exposure"](
            {"server": "Apache/2.4.65 php/8.4.26", "x-powered-by": "PHP/8.4.26"}
        )
        self.assertEqual(len(findings), 2)

    def test_http_collection_preserves_header_findings(self):
        headers = Message()
        headers["X-Powered-By"] = "PHP/8.4.26"
        headers["Content-Type"] = "text/html"
        candidate = {"url": "http://localhost/", "port": 80, "scheme": "http"}
        response = MagicMock()
        response.__enter__.return_value = response
        response.headers = headers
        response.read.return_value = b"<title>Example</title>"
        response.getcode.return_value = 200
        response.geturl.return_value = candidate["url"]
        with patch.object(urllib.request, "urlopen", return_value=response) as request:
            result = self.ns["fetch_http_endpoint"](candidate)
            self.assertEqual(request.call_args.args[0].method, "GET")
            self.assertEqual(request.call_count, 1)
        self.assertEqual(len(result["php_cve_findings"]), 2)
        self.assertEqual(result["security_header_findings"], [self.existing])
        self.assertEqual(len(self.hints), 3)
        with patch.object(
            urllib.request,
            "urlopen",
            side_effect=urllib.error.HTTPError(
                candidate["url"], 403, "Forbidden", headers, None
            ),
        ):
            result = self.ns["fetch_http_endpoint"](candidate)
            self.assertEqual(result["status_code"], 403)
            self.assertEqual(len(result["php_cve_findings"]), 2)
        with patch.object(
            urllib.request, "urlopen", side_effect=OSError("unreachable")
        ):
            result = self.ns["fetch_http_endpoint"](candidate)
            self.assertEqual(result["php_cve_findings"], [])
            self.assertFalse(result["reachable"])


if __name__ == "__main__":
    unittest.main()
