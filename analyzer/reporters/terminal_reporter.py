# analyzer/reporters/terminal_reporter.py

from analyzer.core.models import ScanResult

# ANSI color codes
RESET  = "\033[0m"
BOLD   = "\033[1m"
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
WHITE  = "\033[97m"

LEVEL_COLORS = {
    "CLEAN":    GREEN,
    "LOW":      CYAN,
    "MEDIUM":   YELLOW,
    "HIGH":     RED,
    "CRITICAL": RED + BOLD,
}

SEVERITY_COLORS = {
    range(1, 4):  GREEN,
    range(4, 7):  YELLOW,
    range(7, 11): RED,
}


def _severity_color(severity: int) -> str:
    for r, color in SEVERITY_COLORS.items():
        if severity in r:
            return color
    return RESET


def render(result: ScanResult) -> str:
    lines = []

    # --- Header ---
    lines.append(f"\n{BOLD}{'='*60}{RESET}")
    lines.append(f"{BOLD}  EMAIL THREAT ANALYZER — SCAN REPORT{RESET}")
    lines.append(f"{BOLD}{'='*60}{RESET}")

    # --- Email summary ---
    lines.append(f"\n{BOLD}EMAIL SUMMARY{RESET}")
    lines.append(f"  Subject   : {result.email.subject}")
    lines.append(f"  From      : {result.email.sender}")
    lines.append(f"  Reply-To  : {result.email.reply_to or 'N/A'}")
    lines.append(f"  Date      : {result.email.date or 'N/A'}")
    lines.append(f"  Scanned At: {result.scanned_at}")

    # --- Threat score ---
    level_color = LEVEL_COLORS.get(result.threat_level, WHITE)
    lines.append(f"\n{BOLD}THREAT ASSESSMENT{RESET}")
    lines.append(f"  Score : {BOLD}{result.threat_score}/100{RESET}")
    lines.append(f"  Level : {level_color}{BOLD}{result.threat_level}{RESET}")

    # --- Indicators ---
    lines.append(f"\n{BOLD}INDICATORS ({len(result.indicators)} found){RESET}")

    if not result.indicators:
        lines.append(f"  {GREEN}No suspicious indicators detected.{RESET}")
    else:
        for i, indicator in enumerate(result.indicators, 1):
            color = _severity_color(indicator.severity)
            lines.append(f"\n  [{i}] {BOLD}{indicator.name}{RESET} "
                         f"[{color}severity {indicator.severity}{RESET}] "
                         f"({indicator.category})")
            lines.append(f"      {indicator.description}")
            lines.append(f"      Evidence: {CYAN}{indicator.evidence}{RESET}")

    lines.append(f"\n{BOLD}{'='*60}{RESET}\n")
    return "\n".join(lines)