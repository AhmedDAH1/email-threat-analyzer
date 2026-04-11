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


def run_analysis(eml_path: str, vt_api_key: str | None = None) -> ScanResult:
    """Parse the .eml file and run all analyzers."""

    with open(eml_path, "r", encoding="utf-8", errors="replace") as f:
        raw = f.read()

    email = parse_email(raw)

    indicators = []
    indicators += analyze_headers(email)
    indicators += analyze_urls(email, api_key=vt_api_key)
    indicators += analyze_attachments(email, api_key=vt_api_key)
    indicators += analyze_content(email)

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
    parser.add_argument(
        "--virustotal",
        help="VirusTotal API key to enable URL and file hash lookups",
        default=None,
        metavar="API_KEY"
    )

    args = parser.parse_args()

    if args.virustotal:
        print("[+] VirusTotal integration enabled")

    try:
        result = run_analysis(args.eml_file, vt_api_key=args.virustotal)
    except FileNotFoundError:
        print(f"[ERROR] File not found: {args.eml_file}")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] Failed to analyze file: {e}")
        sys.exit(1)

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