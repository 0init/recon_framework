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
        apt-get install -y python3 python3-pip python3-venv git curl wget
        ;;
    "CentOS Linux")
        yum -y update
        yum -y install python3 python3-pip git curl wget
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

# Create directory for tools
mkdir -p /opt/recon-tools
cd /opt/recon-tools

# Install Go (required for some tools)
echo "Installing Go..."
GO_VERSION="1.22.0"
ARCH=$(uname -m)
if [ "$ARCH" = "x86_64" ]; then
    GO_ARCH="amd64"
elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
    GO_ARCH="arm64"
else
    echo "Unsupported architecture: $ARCH"
    exit 1
fi

wget https://go.dev/dl/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz
rm -rf /usr/local/go && tar -C /usr/local -xzf go${GO_VERSION}.linux-${GO_ARCH}.tar.gz
export PATH=$PATH:/usr/local/go/bin
echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/bash.bashrc
source /etc/profile
rm go${GO_VERSION}.linux-${GO_ARCH}.tar.gz

# Create directory for Go binaries and add to PATH
mkdir -p /opt/go/bin
echo 'export GOPATH=/opt/go' >> /etc/profile
echo 'export PATH=$PATH:/opt/go/bin' >> /etc/profile
echo 'export GOPATH=/opt/go' >> /etc/bash.bashrc
echo 'export PATH=$PATH:/opt/go/bin' >> /etc/bash.bashrc
export GOPATH=/opt/go
export PATH=$PATH:/opt/go/bin

# Install external tools
echo "Installing external tools..."

# Install subfinder
echo "Installing subfinder..."
GO111MODULE=on go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
if [ ! -f "$GOPATH/bin/subfinder" ]; then
    echo "Failed to install subfinder. Trying alternative method..."
    cd /opt/recon-tools
    git clone https://github.com/projectdiscovery/subfinder.git
    cd subfinder/v2/cmd/subfinder
    go build .
    cp subfinder /usr/local/bin/
fi
ln -sf $GOPATH/bin/subfinder /usr/local/bin/subfinder 2>/dev/null || true

# Install assetfinder
echo "Installing assetfinder..."
go install -v github.com/tomnomnom/assetfinder@latest
if [ ! -f "$GOPATH/bin/assetfinder" ]; then
    echo "Failed to install assetfinder. Trying alternative method..."
    cd /opt/recon-tools
    git clone https://github.com/tomnomnom/assetfinder.git
    cd assetfinder
    go build .
    cp assetfinder /usr/local/bin/
fi
ln -sf $GOPATH/bin/assetfinder /usr/local/bin/assetfinder 2>/dev/null || true

# Install naabu
echo "Installing naabu..."
GO111MODULE=on go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
if [ ! -f "$GOPATH/bin/naabu" ]; then
    echo "Failed to install naabu. Trying alternative method..."
    cd /opt/recon-tools
    git clone https://github.com/projectdiscovery/naabu.git
    cd naabu/v2/cmd/naabu
    go build .
    cp naabu /usr/local/bin/
fi
ln -sf $GOPATH/bin/naabu /usr/local/bin/naabu 2>/dev/null || true

# Install nuclei
echo "Installing nuclei..."
GO111MODULE=on go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
if [ ! -f "$GOPATH/bin/nuclei" ]; then
    echo "Failed to install nuclei. Trying alternative method..."
    cd /opt/recon-tools
    git clone https://github.com/projectdiscovery/nuclei.git
    cd nuclei/v3/cmd/nuclei
    go build .
    cp nuclei /usr/local/bin/
fi
ln -sf $GOPATH/bin/nuclei /usr/local/bin/nuclei 2>/dev/null || true

# Clone nuclei-templates
echo "Cloning nuclei-templates..."
git clone https://github.com/projectdiscovery/nuclei-templates.git /opt/nuclei-templates

# Return to the framework directory
cd "$(dirname "$0")"

# Create virtual environment and install Python dependencies
echo "Installing Python dependencies..."
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Create config directory if it doesn't exist
mkdir -p config

# Detect tool paths
SUBFINDER_PATH=$(which subfinder)
ASSETFINDER_PATH=$(which assetfinder)
NAABU_PATH=$(which naabu)
NUCLEI_PATH=$(which nuclei)

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
subfinder = ${SUBFINDER_PATH}
assetfinder = ${ASSETFINDER_PATH}
naabu = ${NAABU_PATH}
nuclei = ${NUCLEI_PATH}

[targets]
domains = ["example.com"]
EOF
    echo "Please edit config/.config to add your target domains and API keys."
fi

echo "Installation completed successfully!"
echo "To run the reconnaissance framework:"
echo "1. Activate the virtual environment: source venv/bin/activate"
echo "2. Run the framework: python main.py --config config/.config"
