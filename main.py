# main.py

import argparse
import sys
from analyzer.engine import analyze_file as run_analysis
from analyzer.reporters import terminal_reporter, json_reporter


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