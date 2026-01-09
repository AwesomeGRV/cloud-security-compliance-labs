#  Essential Cloud Security Tools

##  Overview

This guide covers the essential tools you'll need for cloud security learning and practice. We'll cover command-line tools, security scanners, monitoring solutions, and development environments that will help you build, test, and secure cloud infrastructure.

##  Learning Objectives

By the end of this guide, you will:
- Master essential cloud security tools
- Understand tool selection criteria
- Be able to automate security tasks
- Create effective security workflows
- Set up comprehensive monitoring

##  Tool Categories

### 1. Cloud Platform Tools
- **Azure CLI**, **AWS CLI**, **Google Cloud CLI**
- **Terraform**, **Pulumi**, **CloudFormation**
- **Docker**, **Kubernetes**

### 2. Security Scanning Tools
- **Prowler**, **ScoutSuite**, **CloudSploit**
- **Checkov**, **tfsec**, **Terrascan**
- **Trivy**, **Grype**, **Clair**

### 3. Monitoring & Logging
- **Prometheus**, **Grafana**, **ELK Stack**
- **CloudWatch**, **Azure Monitor**
- **Falco**, **Sysdig**

### 4. Development & Testing
- **VS Code**, **IntelliJ**, **Vim**
- **Postman**, **Burp Suite**, **OWASP ZAP**
- **Git**, **GitHub Actions**, **Jenkins**

##  Cloud Platform Tools

### Azure CLI
```bash
# Installation
# Windows
winget install Microsoft.AzureCLI

# macOS
brew install azure-cli

# Linux
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

# Basic Usage
az login                    # Login to Azure
az account list            # List subscriptions
az group create -n rg-name -l eastus  # Create resource group
az vm list                 # List virtual machines
az storage account list    # List storage accounts

# Useful Commands for Security
az ad user list            # List Azure AD users
az role assignment list    # List role assignments
az network nsg list        # List network security groups
az monitor activity-log list  # List activity logs
```

### AWS CLI
```bash
# Installation
# Windows
winget install Amazon.AWSCLI

# macOS
brew install awscli

# Linux
sudo apt-get install awscli

# Configuration
aws configure

# Basic Usage
aws ec2 describe-instances    # List EC2 instances
aws s3 ls                    # List S3 buckets
aws iam list-users           # List IAM users
aws cloudwatch describe-alarms  # List CloudWatch alarms

# Security Commands
aws iam get-account-authorization-details  # Get account permissions
aws ec2 describe-security-groups          # List security groups
aws s3api get-bucket-policy --bucket name # Get bucket policy
aws logs describe-log-groups              # List CloudWatch log groups
```

### Google Cloud CLI
```bash
# Installation
# Windows
winget install Google.CloudSDK

# macOS
brew install google-cloud-sdk

# Linux
curl https://sdk.cloud.google.com | bash

# Configuration
gcloud init
gcloud auth login

# Basic Usage
gcloud compute instances list      # List compute instances
gcloud storage buckets list        # List Cloud Storage buckets
gcloud iam service-accounts list   # List service accounts

# Security Commands
gcloud projects get-iam-policy PROJECT_ID  # Get IAM policy
gcloud compute firewall-rules list          # List firewall rules
gcloud logging logs list                   # List log entries
```

##  Infrastructure as Code Tools

### Terraform
```bash
# Installation
# Windows
winget install Hashicorp.Terraform

# macOS
brew install terraform

# Linux
wget https://releases.hashicorp.com/terraform/1.6.0/terraform_1.6.0_linux_amd64.zip
unzip terraform_1.6.0_linux_amd64.zip
sudo mv terraform /usr/local/bin/

# Basic Workflow
terraform init      # Initialize working directory
terraform plan      # Show execution plan
terraform apply     # Apply changes
terraform destroy   # Destroy infrastructure
terraform fmt       # Format configuration files
terraform validate  # Validate configuration files

# Security Commands
terraform show      # Show current state
terraform state list  # List resources in state
terraform graph     # Visualize dependency graph
```

#### Example Terraform Configuration
```hcl
# main.tf
provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "example" {
  name     = "security-lab-rg"
  location = "eastus"
}

resource "azurerm_network_security_group" "example" {
  name                = "lab-nsg"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  security_rule {
    name                       = "allow-ssh"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}
```

### Pulumi
```bash
# Installation
# Windows
winget install Pulumi.Pulumi

# macOS
brew install pulumi

# Linux
curl -fsSL https://get.pulumi.com | sh

# Basic Usage
pulumi new aws-typescript  # Create new project
pulumi up                  # Deploy infrastructure
pulumi stack ls            # List stacks
pulumi destroy             # Destroy stack
```

##  Security Scanning Tools

### Prowler (AWS Security)
```bash
# Installation
pip install prowler

# Basic Usage
prowler aws                 # Scan AWS account
prowler aws -p profile-name # Scan specific profile
prowler aws -M csv,html     # Output in multiple formats

# Specific Checks
prowler aws -c iam_check    # Run specific check
prowler aws -g cislevel1    # Run CIS Level 1 checks
prowler aws -e s3,iam       # Exclude services

# Advanced Usage
prowler aws --log-level DEBUG    # Debug mode
prowler aws --output-dir /path   # Custom output directory
```

### ScoutSuite (Multi-Cloud)
```bash
# Installation
pip install scoutsuite

# Basic Usage
scoutsuite aws                    # Scan AWS
scoutsuite azure                  # Scan Azure
scoutsuite gcp                    # Scan GCP

# Advanced Options
scoutsuite aws --profile profile-name  # Use specific profile
scoutsuite aws --regions us-east-1,us-west-2  # Specific regions
scoutsuite aws --services s3,ec2,iam  # Specific services

# Report Generation
scoutsuite aws --report-dir ./reports  # Custom report directory
scoutsuite aws --format html,json     # Multiple formats
```

### Checkov (IaC Security)
```bash
# Installation
pip install checkov

# Basic Usage
checkov -d .                    # Scan current directory
checkov -f main.tf             # Scan specific file
checkov -b .                   # Scan Git repository

# Framework Support
checkov -f main.tf --framework terraform  # Terraform files
checkov -f template.yaml --framework cloudformation  # CloudFormation
checkov -f dockerfile --framework dockerfile  # Dockerfiles

# Advanced Options
checkov -d . --soft-fail       # Continue on failures
checkov -d . --output json     # JSON output
checkov -d . --external-checks-dir /path  # Custom checks
```

### Trivy (Container & File Scanner)
```bash
# Installation
# Windows
winget install aquasecurity.trivy

# macOS
brew install trivy

# Linux
sudo apt-get install wget apt-transport-https gnupg lsb-release
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install trivy

# Basic Usage
trivy image nginx:latest        # Scan Docker image
trivy fs .                     # Scan filesystem
trivy repo https://github.com/user/repo  # Scan repository

# Advanced Options
trivy image --severity HIGH,CRITICAL nginx:latest  # Filter severity
trivy image --format json --output report.json nginx:latest  # JSON output
trivy fs --skip-dirs /tmp,/var  # Skip directories
```

##  Monitoring & Logging Tools

### Prometheus
```bash
# Installation
docker run -d \
  --name prometheus \
  -p 9090:9090 \
  -v prometheus-data:/prometheus \
  prom/prometheus

# Configuration (prometheus.yml)
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']
  
  - job_name: 'node-exporter'
    static_configs:
      - targets: ['localhost:9100']

# Query Examples
up                              # Check if targets are up
rate(cpu_usage_total[5m])      # CPU usage rate
container_memory_usage_bytes   # Memory usage
```

### Grafana
```bash
# Installation
docker run -d \
  --name grafana \
  -p 3000:3000 \
  -e "GF_SECURITY_ADMIN_PASSWORD=admin" \
  grafana/grafana

# Basic Configuration
# Access: http://localhost:3000
# Default credentials: admin/admin

# Add Prometheus Data Source
# 1. Go to Configuration > Data Sources
# 2. Add Prometheus
# 3. URL: http://prometheus:9090
# 4. Save & Test
```

### ELK Stack (Elasticsearch, Logstash, Kibana)
```bash
# Using Docker Compose
version: '3.7'
services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:7.15.0
    environment:
      - discovery.type=single-node
      - "ES_JAVA_OPTS=-Xms512m -Xmx512m"
    ports:
      - "9200:9200"
  
  logstash:
    image: docker.elastic.co/logstash/logstash:7.15.0
    ports:
      - "5044:5044"
    volumes:
      - ./logstash.conf:/usr/share/logstash/pipeline/logstash.conf
  
  kibana:
    image: docker.elastic.co/kibana/kibana:7.15.0
    ports:
      - "5601:5601"
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
```

##  Testing & Development Tools

### VS Code Extensions
```bash
# Essential Extensions for Cloud Security
code --install-extension ms-vscode.vscode-json
code --install-extension ms-azuretools.vscode-docker
code --install-extension ms-vscode.vscode-terraform
code --install-extension ms-vscode.azurecli
code --install-extension AmazonWebServices.aws-toolkit-vscode
code --install-extension GoogleCloudTools.cloudcode
code --install-extension ms-kubernetes-tools.vscode-kubernetes-tools
code --install-extension redhat.vscode-yaml
code --install-extension ms-vscode.powershell
```

### Postman (API Testing)
```bash
# Installation
# Download from https://www.postman.com/downloads/

# Cloud Security API Testing Examples
# 1. AWS Security Token Service
POST https://sts.amazonaws.com/
Headers:
  Content-Type: application/x-www-form-urlencoded
Body:
  Action=GetCallerIdentity&Version=2011-06-15

# 2. Azure REST API
GET https://management.azure.com/subscriptions/{subscription-id}/resourceGroups?api-version=2021-04-01
Headers:
  Authorization: Bearer {access-token}
```

### OWASP ZAP (Web Security Testing)
```bash
# Installation
# Download from https://www.zaproxy.org/download/

# Basic Usage
# 1. Start ZAP
# 2. Target: http://your-web-app
# 3. Active Scan: Automatically scan for vulnerabilities
# 4. Spider: Discover application structure

# Command Line
zap.sh -cmd -quickurl http://target-app.com
zap.sh -cmd -quickprogress -quickurl http://target-app.com
```

##  Automation & Scripting

### PowerShell for Azure
```powershell
# Connect to Azure
Connect-AzAccount

# Get all resources in subscription
Get-AzResource | Format-Table Name, ResourceType, Location

# Security Assessment Script
function Get-AzSecurityStatus {
    param($ResourceGroupName)
    
    Write-Host "=== Security Assessment for $ResourceGroupName ==="
    
    # Check Network Security Groups
    $nsgs = Get-AzNetworkSecurityGroup -ResourceGroupName $ResourceGroupName
    foreach ($nsg in $nsgs) {
        Write-Host "NSG: $($nsg.Name)"
        $nsg.SecurityRules | Format-Table Name, Direction, Access, Protocol, PortRange
    }
    
    # Check VM Security
    $vms = Get-AzVM -ResourceGroupName $ResourceGroupName
    foreach ($vm in $vms) {
        Write-Host "VM: $($vm.Name)"
        Write-Host "  OS Type: $($vm.StorageProfile.OSDisk.OSType)"
        Write-Host "  Size: $($vm.HardwareProfile.VmSize)"
    }
}

# Usage
Get-AzSecurityStatus -ResourceGroupName "security-lab"
```

### Python for AWS Security
```python
#!/usr/bin/env python3
import boto3
import json

def aws_security_assessment():
    """Perform basic AWS security assessment"""
    
    # Initialize AWS clients
    ec2 = boto3.client('ec2')
    iam = boto3.client('iam')
    s3 = boto3.client('s3')
    
    print("=== AWS Security Assessment ===")
    
    # Check EC2 security groups
    print("\n1. Security Groups:")
    security_groups = ec2.describe_security_groups()
    for sg in security_groups['SecurityGroups']:
        print(f"  SG: {sg['GroupId']} - {sg['GroupName']}")
        for rule in sg['IpPermissions']:
            print(f"    {rule['IpProtocol']} - {rule.get('FromPort', 'All')}-{rule.get('ToPort', 'All')}")
    
    # Check IAM users
    print("\n2. IAM Users:")
    users = iam.list_users()
    for user in users['Users']:
        print(f"  User: {user['UserName']} - Created: {user['CreateDate']}")
    
    # Check S3 buckets
    print("\n3. S3 Buckets:")
    buckets = s3.list_buckets()
    for bucket in buckets['Buckets']:
        print(f"  Bucket: {bucket['Name']} - Created: {bucket['CreationDate']}")
        
        # Check bucket policy
        try:
            policy = s3.get_bucket_policy(Bucket=bucket['Name'])
            print(f"    Policy: {policy['Policy']}")
        except:
            print("    Policy: No public policy")

if __name__ == "__main__":
    aws_security_assessment()
```

##  Tool Integration Workflows

### Security Scanning Pipeline
```yaml
# .github/workflows/security-scan.yml
name: Security Scan

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Setup Terraform
      uses: hashicorp/setup-terraform@v2
    
    - name: Terraform Format Check
      run: terraform fmt -check
    
    - name: Terraform Security Scan
      run: |
        pip install checkov
        checkov -d . --soft-fail
    
    - name: Container Security Scan
      run: |
        docker build -t app .
        wget https://github.com/aquasecurity/trivy/releases/download/v0.34.0/trivy_0.34.0_Linux-64bit.tar.gz
        tar xzf trivy_0.34.0_Linux-64bit.tar.gz
        ./trivy image --format json --output trivy-report.json app
```

### Automated Monitoring Setup
```bash
#!/bin/bash
# setup-monitoring.sh

echo "Setting up monitoring infrastructure..."

# Create monitoring namespace
kubectl create namespace monitoring

# Deploy Prometheus
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update
helm install prometheus prometheus-community/kube-prometheus-stack -n monitoring

# Deploy Grafana dashboards
kubectl apply -f grafana-dashboards/

echo "Monitoring setup complete!"
echo "Access Grafana: kubectl port-forward -n monitoring svc/prometheus-grafana 3000:3000"
```

##  Tool Selection Criteria

### When choosing tools, consider:

1. **Platform Compatibility**
   - Does it support your cloud providers?
   - Cross-platform capabilities?
   - Integration with existing tools?

2. **Ease of Use**
   - Learning curve and documentation
   - Community support
   - Available tutorials and examples

3. **Cost**
   - Open source vs commercial
   - Licensing requirements
   - Total cost of ownership

4. **Features**
   - Required security capabilities
   - Reporting and alerting
   - Automation and scripting support

##  Best Practices

### Tool Management
- **Version Control**: Keep track of tool versions
- **Documentation**: Document tool configurations
- **Regular Updates**: Keep tools updated for security
- **Backup**: Backup configurations and data

### Security Considerations
- **Credentials**: Store securely using vaults
- **Access**: Limit tool access to authorized users
- **Audit**: Monitor tool usage and activities
- **Compliance**: Ensure tools meet compliance requirements

##  Next Steps

With these tools mastered, you're ready to:

1. **[Complete Your First Lab](first-lab.md)** - Apply tools in practice
2. **[Explore Core Security Areas](../core/)** - Deep dive into security domains
3. **[Build Security Automation](../devsecops/)** - Automate security processes

---

** Your security toolkit is now complete!** Start building and securing cloud infrastructure with confidence.
