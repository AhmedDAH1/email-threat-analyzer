# main.py

import argparse
import sys
from analyzer.core.parser import parse_email
from analyzer.core.models import ScanResult
from analyzer.core.scorer import score_result
from analyzer.analyzers.header_analyzer import analyze_headers
from analyzer.analyzers.url_analyzer import analyze_urls
from analyzer.analyzers.attachment_analyzer import analyze_attachments
from analyzer.analyzers.content_analyzer import analyze_content
from analyzer.reporters import terminal_reporter, json_reporter


def run_analysis(eml_path: str) -> ScanResult:
    """Parse the .eml file and run all analyzers."""

    # Step 1 — Parse raw .eml into structured EmailMessage
    with open(eml_path, "r", encoding="utf-8", errors="replace") as f:
        raw = f.read()

    email = parse_email(raw)


    # Step 2 — Run all analyzers, collect indicators
    indicators = []
    indicators += analyze_headers(email)
    indicators += analyze_urls(email)
    indicators += analyze_attachments(email)
    indicators += analyze_content(email)

    # Step 3 — Build ScanResult and score it
    result = ScanResult(email=email, indicators=indicators)
    result = score_result(result)

    return result


def main():
    parser = argparse.ArgumentParser(
        prog="email-threat-analyzer",
        description="Analyze .eml files for phishing indicators."
    )
    parser.add_argument(
        "eml_file",
        help="Path to the .eml file to analyze"
    )
    parser.add_argument(
        "--format",
        choices=["terminal", "json"],
        default="terminal",
        help="Output format (default: terminal)"
    )
    parser.add_argument(
        "--output",
        help="Save JSON report to a file (only with --format json)",
        default=None
    )

    args = parser.parse_args()

    # Validate file
    try:
        result = run_analysis(args.eml_file)
    except FileNotFoundError:
        print(f"[ERROR] File not found: {args.eml_file}")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] Failed to analyze file: {e}")
        sys.exit(1)

    # Output
    if args.format == "json":
        output = json_reporter.render(result)
        print(output)
        if args.output:
            json_reporter.save(result, args.output)
            print(f"\n[+] Report saved to {args.output}")
    else:
        print(terminal_reporter.render(result))


if __name__ == "__main__":
    main()