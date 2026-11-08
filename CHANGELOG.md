# Changelog

All notable changes to Email Threat Analyzer. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.3.0] - 2026-11-08

### Added
- The web API's `POST /api/analyze` response includes `soar`: the verdict in
  the format `--forward` sends to SOAR-Lite, so SOAR-Lite's "Analyze logs"
  page can open an incident from an uploaded email.

## [1.2.0] - 2026-11-08

### Added
- `--forward URL` sends a verdict to [SOAR-Lite](https://github.com/AhmedDAH1/soar-lite)
  as an incident, signed with HMAC-SHA256 (`SOAR_WEBHOOK_SECRET`).
  `--forward-min` (default `MEDIUM`) keeps low verdicts local; if SOAR-Lite
  is down, the analysis still completes.

### Security
- The web interface escapes error messages before displaying them, like the
  rest of the report.
