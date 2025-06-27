# JSX-Ray: JavaScript Recon Tool

JSX-Ray scans internal JavaScript files from a target website to extract:
- Hidden API endpoints or URLs
- Sensitive parameters like `token`, `auth`, `key`, `debug`
- Hardcoded secrets or credentials

## Usage

```bash
python jsxray.py --url https://example.com --output url_results.json --threads 10 --save-js

python jsxray.py --list list.txt --output list_results.json --threads 10 --save-js

python jsxray.py --js-list https://example.com --output results_js.json --threads 10 --save-js
```

## Features
- Extract internal JS file links
- Scan JS content for URLs, secrets, and sensitive keywords
- Save raw JS files (optional)
- Multithreaded for speed
- Outputs color-coded findings to terminal
- Saves report in JSON format

## Requirements
```
pip install -r requirements.txt
```
