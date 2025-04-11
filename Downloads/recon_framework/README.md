# Automated Reconnaissance and Vulnerability Scanning Framework

A comprehensive framework for automating the discovery and security assessment of web assets. This framework consists of four core modules that work together to identify subdomains, discover active hosts, scan for vulnerabilities, and send notifications about security findings.

## Features

- **Subdomain Enumeration**: Identifies subdomains for target domains using tools like subfinder and assetfinder
- **Host Discovery**: Identifies active web hosts from discovered subdomains using naabu for port scanning
- **Vulnerability Scanning**: Performs security assessments using Acunetix, Nuclei, and VirusTotal
- **Notification System**: Delivers alerts via email (Gmail) and Discord webhooks based on severity

## Architecture

The framework is designed with modularity in mind, allowing each component to function independently while also working together as a cohesive system:

```
recon_framework/
├── subdomain_enum/      # Subdomain enumeration module
├── host_discovery/      # Host discovery module
├── scan/                # Vulnerability scanning module
├── notification/        # Notification module
├── utils/               # Utility functions and helpers
├── config/              # Configuration files
└── tests/               # Test suite
```

## Installation

### Prerequisites

- Python 3.8+
- MongoDB
- External tools:
  - subfinder
  - assetfinder
  - naabu
  - nuclei

### Setup

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/recon_framework.git
   cd recon_framework
   ```

2. Install Python dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Configure MongoDB:
   - Install MongoDB if not already installed
   - Create a database for the framework
   - Update the configuration file with your MongoDB details

4. Install external tools:
   - Follow the installation instructions for subfinder, assetfinder, naabu, and nuclei
   - Update the configuration file with the paths to these tools

5. Create a configuration file:
   - Copy `config/sample_config.ini` to `config/.config`
   - Update the configuration with your settings

## Configuration

The framework uses a configuration file to store settings. A sample configuration file is provided at `config/sample_config.ini`. The configuration includes:

- MongoDB connection details
- API keys for VirusTotal
- Gmail credentials for urgent notifications
- Discord webhook URL for notifications
- Acunetix server details
- Paths to required tools
- Target domains to scan

Example configuration:

```ini
[mongodb]
host = localhost
port = 27017
database = recon_framework

[virustotal]
api_key = ["your_virustotal_api_key1", "your_virustotal_api_key2"]

[gmail]
username = your_gmail_username
password = your_gmail_app_password

[discord]
webhook_url = https://discord.com/api/webhooks/your_webhook_url

[acunetix]
servers = [
    {"url": "https://acunetix_server1", "api_key": "your_acunetix_api_key1"},
    {"url": "https://acunetix_server2", "api_key": "your_acunetix_api_key2"}
]

[nuclei]
templates_path = /path/to/your/nuclei-templates/

[tools]
subfinder = /usr/bin/subfinder
assetfinder = /usr/bin/assetfinder
naabu = /usr/bin/naabu
nuclei = /usr/bin/nuclei

[targets]
domains = ["example.com", "example.org"]
```

## Usage

### Basic Usage

Run the framework with default settings:

```
python -m recon_framework.main
```

### Command-line Options

The framework supports several command-line options:

- `-c, --config`: Path to configuration file
- `-d, --domains`: Target domains to scan (overrides configuration file)
- `-m, --module`: Specific module to run (`all`, `subdomain`, `host`, `scan`, `notify`)
- `-v, --verbose`: Enable verbose logging

Examples:

```
# Run with a specific configuration file
python -m recon_framework.main --config /path/to/your/config.ini

# Run only the subdomain enumeration module
python -m recon_framework.main --module subdomain

# Scan specific domains
python -m recon_framework.main --domains example.com example.org

# Enable verbose logging
python -m recon_framework.main --verbose
```

## Module Details

### Subdomain Enumeration Module

This module identifies subdomains for target domains using tools like subfinder and assetfinder. It stores discovered subdomains in MongoDB and implements a deduplication process to ensure only unique subdomains are retained.

Key features:
- Integration with multiple subdomain discovery tools
- Robust deduplication process
- Incremental updates to avoid rescanning known subdomains
- Structured storage in MongoDB

### Host Discovery Module

This module identifies active web hosts from discovered subdomains using naabu for port scanning. It scans the top 100 common web service ports and stores identified hosts in MongoDB.

Key features:
- Port scanning with naabu
- Prioritization of recently discovered subdomains
- Tracking of scan status for each host

### Scan Module

This module performs vulnerability scanning and analysis on newly discovered hosts using Acunetix, Nuclei, and VirusTotal.

Key features:
- Integration with Acunetix for comprehensive vulnerability scanning
- Integration with Nuclei for template-based scanning
- Integration with VirusTotal for reputation and threat intelligence
- Tracking of scan status for each host

### Notification Module

This module delivers alerts and notifications based on scan results or other events. It supports email notifications via Gmail for urgent alerts and Discord notifications for all alerts.

Key features:
- Severity-based notification routing
- Email notifications for urgent alerts
- Discord notifications with rich embeds
- Structured storage of notification history

## Data Storage

The framework uses MongoDB for data storage with the following collections:

- `subdomains_monitor`: Stores information about monitored domains and their subdomains
- `new_discovered_subdomains`: Stores newly discovered subdomains
- `new_hosts_discovered`: Stores discovered hosts with open web ports
- `notifications`: Stores notification data

## Testing

Run the test suite to verify the framework functionality:

```
python -m recon_framework.tests.test_framework
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
