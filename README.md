# CyberSafeX Detection Suite

A comprehensive digital forensics and security analysis tool built with Python and Flask.

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-3.0-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

## Features

- **File Signature Analysis** - Identify file types using magic numbers and detect file format forgeries
- **Security & Malware Detection** - Scan files for known malware signatures and suspicious patterns
- **Metadata Extraction** - Extract EXIF data, document properties, and hidden information
- **URL Analysis** - Analyze URLs for security vulnerabilities and SSL configuration
- **Timeline Analysis** - Create activity timelines and detect anomalies
- **Interactive Visualizations** - Plotly-powered charts and graphs

## Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

### Setup

1. Clone the repository:
```bash
git clone https://github.com/yourusername/CyberSafeX-Detection-Suite.git
cd CyberSafeX-Detection-Suite
```

2. Create a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Web Interface (Recommended)

Start the Flask web server:
```bash
python app.py
```

Then open your browser and navigate to `http://localhost:5000`

### Command Line Interface

Run the CLI tool:
```bash
python main.py
```

Follow the prompts to:
1. Enter case name and description
2. Provide investigator name
3. Specify evidence path
4. Choose output directory

## Project Structure

```
CyberSafeX-Detection-Suite/
├── app.py                 # Flask web application
├── main.py                # Main forensics module & CLI
├── forensics_tool.py      # Core forensic analysis tools
├── url_analyzer.py        # URL security analysis
├── requirements.txt       # Python dependencies
├── templates/             # HTML templates
│   ├── base.html
│   ├── index.html
│   ├── dashboard.html
│   ├── history.html
│   └── feature.html
├── static/                # Static assets
│   ├── css/
│   └── js/
├── uploads/               # Uploaded files (created automatically)
└── cases/                 # Case data (created automatically)
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Home page with analysis forms |
| `/analyze-file` | POST | Analyze uploaded file |
| `/analyze-url` | POST | Analyze URL |
| `/dashboard` | GET | Analytics dashboard |
| `/history` | GET | Analysis history |
| `/feature/<id>` | GET | Feature details page |

## Security Analysis Capabilities

### File Analysis
- File signature verification (magic numbers)
- Hash calculation (MD5, SHA1, SHA256, SHA512)
- Entropy analysis for encryption detection
- Malware signature scanning
- Suspicious pattern detection
- EXIF metadata extraction

### URL Analysis
- DNS resolution
- SSL/TLS configuration
- Security headers analysis
- Content analysis
- Response time measurement

## Dependencies

- **Flask** - Web framework
- **Pillow** - Image processing
- **Plotly** - Interactive visualizations
- **BeautifulSoup4** - HTML parsing
- **NumPy/Pandas** - Data analysis
- **Requests** - HTTP library

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is intended for educational and legitimate security research purposes only. Always ensure you have proper authorization before analyzing any files or URLs. The authors are not responsible for any misuse of this tool.

## Acknowledgments

- Font Awesome for icons
- Bootstrap for UI components
- Plotly for visualizations
