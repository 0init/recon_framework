#!/bin/bash

# Reconnaissance Framework Installation Script
# This script installs the Reconnaissance Framework and its dependencies on a Linux server

set -e

echo "=== Reconnaissance Framework Installation ==="
echo "This script will install the Reconnaissance Framework and its dependencies."

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root. Please use sudo."
    exit 1
fi

# Detect Linux distribution
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$NAME
    VER=$VERSION_ID
else
    echo "Cannot detect Linux distribution. This script supports Ubuntu, Debian, and CentOS."
    exit 1
fi

echo "Detected OS: $OS $VER"

# Install Python and pip
echo "Installing Python and pip..."
case $OS in
    "Ubuntu" | "Debian GNU/Linux")
        apt-get update
        apt-get install -y python3 python3-pip python3-venv git
        ;;
    "CentOS Linux")
        yum -y update
        yum -y install python3 python3-pip git
        ;;
    *)
        echo "Unsupported OS: $OS"
        exit 1
        ;;
esac

# Install MongoDB
echo "Installing MongoDB..."
case $OS in
    "Ubuntu" | "Debian GNU/Linux")
        # Import MongoDB public GPG key
        apt-get install -y gnupg
        wget -qO - https://www.mongodb.org/static/pgp/server-7.0.asc | apt-key add -
        
        # Create list file for MongoDB
        if [ "$OS" = "Ubuntu" ]; then
            echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu $(lsb_release -cs)/mongodb-org/7.0 multiverse" | tee /etc/apt/sources.list.d/mongodb-org-7.0.list
        else
            echo "deb http://repo.mongodb.org/apt/debian $(lsb_release -cs)/mongodb-org/7.0 main" | tee /etc/apt/sources.list.d/mongodb-org-7.0.list
        fi
        
        apt-get update
        apt-get install -y mongodb-org
        systemctl start mongod
        systemctl enable mongod
        ;;
    "CentOS Linux")
        # Create repo file
        cat > /etc/yum.repos.d/mongodb-org-7.0.repo << EOF
[mongodb-org-7.0]
name=MongoDB Repository
baseurl=https://repo.mongodb.org/yum/redhat/\$releasever/mongodb-org/7.0/x86_64/
gpgcheck=1
enabled=1
gpgkey=https://www.mongodb.org/static/pgp/server-7.0.asc
EOF
        yum install -y mongodb-org
        systemctl start mongod
        systemctl enable mongod
        ;;
esac

# Install Go (required for some tools)
echo "Installing Go..."
wget https://go.dev/dl/go1.22.0.linux-amd64.tar.gz
rm -rf /usr/local/go && tar -C /usr/local -xzf go1.22.0.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
rm go1.22.0.linux-amd64.tar.gz

# Install external tools
echo "Installing external tools..."

# Install subfinder
echo "Installing subfinder..."
GO111MODULE=on go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
ln -sf ~/go/bin/subfinder /usr/local/bin/subfinder

# Install assetfinder
echo "Installing assetfinder..."
go install -v github.com/tomnomnom/assetfinder@latest
ln -sf ~/go/bin/assetfinder /usr/local/bin/assetfinder

# Install naabu
echo "Installing naabu..."
GO111MODULE=on go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
ln -sf ~/go/bin/naabu /usr/local/bin/naabu

# Install nuclei
echo "Installing nuclei..."
GO111MODULE=on go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
ln -sf ~/go/bin/nuclei /usr/local/bin/nuclei

# Clone nuclei-templates
echo "Cloning nuclei-templates..."
git clone https://github.com/projectdiscovery/nuclei-templates.git /opt/nuclei-templates

# Create virtual environment and install Python dependencies
echo "Installing Python dependencies..."
cd "$(dirname "$0")"
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Create config directory if it doesn't exist
mkdir -p config

# Create a basic configuration file if it doesn't exist
if [ ! -f config/.config ]; then
    echo "Creating default configuration file..."
    cat > config/.config << EOF
[mongodb]
host = localhost
port = 27017
database = recon_framework

[virustotal]
api_key = ["your_virustotal_api_key"]

[gmail]
username = your_gmail_username
password = your_gmail_app_password

[discord]
webhook_url = https://discord.com/api/webhooks/your_webhook_url

[acunetix]
servers = [{"url": "https://acunetix_server", "api_key": "your_acunetix_api_key"}]

[nuclei]
templates_path = /opt/nuclei-templates/

[tools]
subfinder = /usr/local/bin/subfinder
assetfinder = /usr/local/bin/assetfinder
naabu = /usr/local/bin/naabu
nuclei = /usr/local/bin/nuclei

[targets]
domains = ["example.com"]
EOF
    echo "Please edit config/.config to add your target domains and API keys."
fi

echo "Installation completed successfully!"
echo "To run the reconnaissance framework:"
echo "1. Activate the virtual environment: source venv/bin/activate"
echo "2. Run the framework: python main.py --config config/.config"
