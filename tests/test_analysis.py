import unittest

from main import analyze_logs, inspect_phishing, password_report, scan_private_host


class CyberSuiteAnalysisTests(unittest.TestCase):
    def test_password_report_returns_bounded_score(self):
        score, tips = password_report("Phrase-Fictive-2026!")
        self.assertGreaterEqual(score, 0)
        self.assertLessEqual(score, 100)
        self.assertTrue(tips)

    def test_password_report_handles_empty_input(self):
        score, tips = password_report("")
        self.assertEqual(score, 0)
        self.assertTrue(tips)

    def test_log_analyzer_finds_authentication_failure(self):
        findings = analyze_logs("normal event\nFailed password for test user")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0][0], "2")
        self.assertIn("Échecs d'authentification", findings[0][1])

    def test_phishing_detector_does_not_open_urls(self):
        findings = inspect_phishing("Urgence : vérifiez votre compte sur http://192.0.2.1/login")
        self.assertTrue(any("adresse IP" in item for item in findings))
        self.assertTrue(any("pressant" in item for item in findings))

    def test_scanner_rejects_public_ip(self):
        with self.assertRaises(ValueError):
            scan_private_host("8.8.8.8")


if __name__ == "__main__":
    unittest.main()
