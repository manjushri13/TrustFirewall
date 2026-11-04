import json
import tempfile
import unittest
from pathlib import Path

from app.security_evaluation import (
    build_security_dataset,
    evaluate_security_dataset,
    write_evaluation_report,
)
from app.models import ThreatCategory


class SecurityEvaluationTests(unittest.TestCase):
    def test_dataset_has_at_least_thirty_labeled_scenarios_and_all_categories(self) -> None:
        scenarios = build_security_dataset()

        self.assertGreaterEqual(len(scenarios), 30)
        self.assertEqual(len({scenario.scenario_id for scenario in scenarios}), len(scenarios))
        labels = {scenario.label for scenario in scenarios}
        self.assertTrue({"benign", "educational", "multi-step-attack"} <= labels)
        expected = {
            category
            for scenario in scenarios
            for category in scenario.expected_categories
        }
        self.assertEqual(expected, set(ThreatCategory))

    def test_offline_evaluation_is_reproducible_and_reports_metrics(self) -> None:
        first = evaluate_security_dataset()
        second = evaluate_security_dataset()

        self.assertEqual(first.dataset_sha256, second.dataset_sha256)
        self.assertEqual(first.model_dump(), second.model_dump())
        self.assertGreaterEqual(first.total_scenarios, 30)
        self.assertGreaterEqual(first.overall_f1, 0.8)
        self.assertEqual(len(first.per_category), len(ThreatCategory))

    def test_live_evaluation_uses_mocked_gemini_and_validates_source_ids(self) -> None:
        def generate(prompt: str) -> str:
            return json.dumps(
                {
                    "threats": [],
                    "relationship": "The proposed action is not influenced by the document.",
                }
            )

        report = evaluate_security_dataset(
            build_security_dataset()[:1],
            live_gemini=True,
            generate=generate,
        )

        self.assertEqual(report.scenarios[0].ai_status, "completed")

    def test_report_writer_creates_reusable_json(self) -> None:
        report = evaluate_security_dataset(build_security_dataset()[:2])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            write_evaluation_report(report, path)
            saved = json.loads(path.read_text(encoding="utf-8"))

        self.assertEqual(saved["dataset_sha256"], report.dataset_sha256)
        self.assertEqual(saved["total_scenarios"], 2)
