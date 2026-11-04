import argparse
from pathlib import Path

from app.security_evaluation import evaluate_security_dataset, write_evaluation_report


def main() -> None:
    parser = argparse.ArgumentParser(description="Run TrustFirewall Phase 5 security evaluation.")
    parser.add_argument("--live-gemini", action="store_true", help="Use Gemini contextual analysis when configured.")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("security_evaluation_report.json"),
        help="Path for the reproducible JSON report.",
    )
    args = parser.parse_args()
    report = evaluate_security_dataset(live_gemini=args.live_gemini)
    write_evaluation_report(report, args.output)
    print(report.model_dump_json(indent=2))


if __name__ == "__main__":
    main()
