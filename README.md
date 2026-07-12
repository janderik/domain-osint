# Domain OSINT

[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

A comprehensive domain intelligence tool for OSINT investigations. Gather DNS records, WHOIS data, SSL certificates, and technology stack information.

## Features

- **DNS enumeration** - Complete DNS record analysis
- **WHOIS lookup** - Domain registration information
- **SSL analysis** - Certificate details and history
- **Technology detection** - Identify website technologies
- **Subdomain discovery** - Find all subdomains
- **Report generation** - Comprehensive HTML/PDF reports

## Installation

```bash
git clone https://github.com/janderik/domain-osint.git
cd domain-osint
pip install -r requirements.txt
```

## Usage

```bash
# Full domain analysis
python cli.py analyze example.com

# DNS lookup
python cli.py dns example.com

# Subdomain enumeration
python cli.py subdomains example.com

# Generate report
python cli.py report example.com --output report.html
```

## Contributing

Contributions are welcome!

## License

MIT License
