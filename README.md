# CyberSafeX Detection Suite

A digital forensics tool that takes an uploaded file or a URL and returns a structured analysis with interactive charts, persisting every run to a searchable history. Flask web app plus a CLI, backed by SQLite.

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-3.0-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)
![Status](https://img.shields.io/badge/status-educational%20project-orange.svg)

> **Scope note.** This is a coursework-scale forensics tool, not a production incident-response
> platform. [What is and is not implemented](#implementation-status) is listed explicitly below,
> because an earlier version of this README advertised capabilities the code does not have.

## Contents

- [What it does](#what-it-does)
- [Implementation status](#implementation-status)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Project structure](#project-structure)
- [Routes](#routes)
- [Engineering notes](#engineering-notes)
- [Known issues](#known-issues)
- [Contributing](#contributing)
- [License](#license)
- [Disclaimer](#disclaimer)

## What it does

### File analysis

- **Hashing** — MD5, SHA1, SHA256 and SHA512 computed in a single pass over 8,192-byte chunks.
- **Shannon entropy, two ways** — whole-file, plus a per-1,024-byte block map. Entropy above **7.5**
  raises a possible-encryption warning and lifts the reported risk level.
- **Byte-level content analysis** — full 256-value frequency distribution and an ASCII-to-binary ratio.
- **Suspicious byte-pattern detection** — three compiled patterns: a NOP sled (`\x90{10,}`), a long
  null-byte run (`(\x00){100,}`), and an inline `<script>` block. Each escalates risk to high.
- **EXIF extraction** — through Pillow's `ExifTags`, with per-tag error isolation.
- **File typing** — `mimetypes.guess_type()`, which is extension-based. See
  [Implementation status](#implementation-status).

### URL analysis

- DNS resolution via `socket.gethostbyname`.
- HTTP GET with a 5-second timeout and redirect tracking.
- Response metadata: status, content type, server, elapsed time, final URL.
- Presence checks for five security headers, scored 20 points each out of 100: HTTPS, HSTS,
  X-XSS-Protection, Content-Security-Policy, X-Frame-Options.
- Content statistics through BeautifulSoup: title, meta description, link, image and script counts.

### Reporting

Four Plotly figures embedded into a single self-contained HTML report:

| Figure | Shows |
|---|---|
| Timeline | File created / modified / accessed timestamps |
| Byte-frequency histogram | 256 bins across the full byte range |
| Entropy map | Shannon entropy against file position in KB |
| Composition donut | ASCII versus binary byte share |

Every run is written to a SQLite `analysis_history` table (id, type, target, result JSON,
timestamp), surfaced through an aggregate dashboard and a history view paginated at 10 per page.

## Implementation status

Listed here so nothing in this README overstates the code.

| Capability | Status |
|---|---|
| Hashing (MD5 / SHA1 / SHA256 / SHA512) | Implemented |
| Shannon entropy, file and block level | Implemented |
| Byte-frequency and ASCII/binary analysis | Implemented |
| Suspicious byte-pattern detection | Implemented — **three regexes**, not a signature database |
| EXIF metadata extraction | Implemented |
| Plotly reporting and SQLite history | Implemented |
| URL DNS, timing, content stats | Implemented |
| Security-header presence checks | Implemented |
| **Magic-number file typing / format forgery detection** | **Not implemented.** `# import magic  # Removed temporarily` sits at line 5 of `forensics_tool.py`; typing falls back to extension-based `mimetypes.guess_type()` |
| **SSL/TLS configuration analysis** | **Not wired up.** `_analyze_ssl`, `_analyze_headers`, `_scan_vulnerabilities`, `_analyze_content` and `_calculate_security_score` exist in `url_analyzer.py` but `analyze_url()` calls none of them. The shipped HTTPS check is `url.startswith('https://')` |
| **Malware signature scanning** | **Not implemented** in the sense the name implies — see suspicious byte patterns above |
| **Memory forensics** | **Not implemented.** No process analysis, no memory-dump parsing, no string extraction |
| Automated tests | None |

Re-adding `python-magic` would make the file-typing claim true and is a small change.

## Requirements

- Python 3.8 or higher
- pip

## Installation

```bash
git clone https://github.com/Ruthvik-Bandari/CyberSafeX-Detection-Suite.git
cd CyberSafeX-Detection-Suite

python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

pip install -r requirements.txt
```

## Usage

### Web interface

```bash
python app.py
```

Then open `http://localhost:5000`.

### Command line

```bash
python main.py
```

The CLI prompts for a case name and description, an investigator name, an evidence path, and an
output directory.

## Project structure

```
CyberSafeX-Detection-Suite/
├── app.py                 # Flask web application (465 lines)
├── main.py                # Forensics module and CLI (1,568 lines)
├── forensics_tool.py      # Core file analysis (554 lines)
├── url_analyzer.py        # URL analysis (337 lines)
├── requirements.txt
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── dashboard.html
│   ├── history.html
│   └── feature.html
├── uploads/               # Created at runtime, cleaned after each analysis
└── cases/                 # Created at runtime
```

## Routes

| Route | Method | Description |
|---|---|---|
| `/` | GET | Home page with analysis forms |
| `/analyze-file` | POST | Analyze an uploaded file |
| `/analyze-url` | POST | Analyze a URL |
| `/dashboard` | GET | Aggregate analytics |
| `/history` | GET | Paginated analysis history |
| `/feature/<id>` | GET | Single-run detail page |
| `/report` | GET | Serve a generated HTML report |

## Engineering notes

Three parts of this codebase were built deliberately and are worth reading:

1. **Path-traversal guard on `/report`.** The route resolves the requested path and verifies the
   workspace root appears in `resolved_path.parents` before serving, so a crafted `path` parameter
   cannot read arbitrary files off disk.

2. **Upload hardening.** `secure_filename` plus a UUID prefix, a 16 MB `MAX_CONTENT_LENGTH` cap, and
   deletion of the uploaded file in a `finally` block, so analysis never leaves artifacts behind.

3. **Recursive JSON normalisation.** `_to_json_safe` walks dicts, lists and tuples to convert
   `datetime` objects and NumPy scalars before serialization, which fixes a whole class of
   "object is not JSON serializable" failures rather than patching them one at a time.

## Known issues

- `requests.get(..., verify=False)` in `url_analyzer.py` disables TLS certificate verification.
- `app.run(debug=True)` ships in both `app.py` and `main.py`. Do not expose either to a network.
- The file-analysis security gauge never renders, because `analyze_file` never sets `security_score`.
- `digital_forensics.log` and a sample `.sqlite` evidence file are committed to the repository.
- No automated tests.

> **Safety note on the dead code.** `_scan_vulnerabilities` in `url_analyzer.py` sends SQL-injection,
> XSS and path-traversal payloads at a target and probes for `/.git/config` and `/.env`. It is never
> called. If you wire it up, run it only against systems you own or have written authorization to
> test. Unsolicited active scanning of third-party sites is unlawful in many jurisdictions.

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Commit your changes
4. Push to the branch
5. Open a pull request

Fixes to anything in [Known issues](#known-issues) or [Implementation status](#implementation-status)
are especially welcome.

## License

MIT — see [LICENSE](LICENSE).

## Disclaimer

For educational and authorized security research only. Ensure you have permission before analyzing
any file or URL. The author is not responsible for misuse.

---

Author: **Ruthvik Nath Bandari** · [GitHub](https://github.com/Ruthvik-Bandari) · [LinkedIn](https://www.linkedin.com/in/ruthvik-nath-bandari/)
