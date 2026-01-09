#  Setting Up Your Cloud Security Lab

##  Overview

This guide will help you set up a comprehensive cloud security lab environment where you can safely practice security concepts without risking production systems. We'll create isolated environments across multiple cloud platforms with proper monitoring and logging.

##  Learning Objectives

By the end of this guide, you will have:
- A secure, isolated lab environment
- Multiple cloud platform accounts configured
- Essential security tools installed
- Monitoring and logging infrastructure
- Cost management controls in place

##  Lab Architecture

### Environment Design
```
┌─────────────────────────────────────────────────────────────┐
│                    Cloud Security Lab                       │
├─────────────────┬─────────────────┬─────────────────────────┤
│   Azure Lab     │    AWS Lab      │      Local Tools        │
│                 │                 │                         │
│ ┌─────────────┐ │ ┌─────────────┐ │ ┌─────────────────────┐ │
│ │ Test VM     │ │ │ Test EC2    │ │ │ Kali Linux          │ │
│ │ Storage     │ │ │ S3 Bucket   │ │ │ Docker              │ │
│ │ Network     │ │ │ VPC         │ │ │ Terraform           │ │
│ │ Monitoring  │ │ │ CloudWatch  │ │ │ VS Code             │ │
│ └─────────────┘ │ └─────────────┘ │ └─────────────────────┘ │
└─────────────────┴─────────────────┴─────────────────────────┘
```

##  Prerequisites

### System Requirements
- **OS**: Windows 10/11, macOS 10.15+, or Ubuntu 20.04+
- **RAM**: Minimum 8GB, recommended 16GB
- **Storage**: 50GB free space
- **Network**: Stable internet connection

### Required Accounts
- Microsoft Azure account (free tier available)
- AWS account (free tier available)
- GitHub account (for code management)

### Software Installation
```bash
# Install package managers (choose based on your OS)
# Windows: Install Chocolatey or Winget
# macOS: Install Homebrew
# Linux: Use apt, yum, or dnf

# We'll install tools throughout this guide
```

##  Account Setup and Security

### 1. Azure Account Setup

#### Create Azure Account
1. Visit [Azure Portal](https://portal.azure.com)
2. Sign up for free account
3. Verify identity and payment method
4. Set up spending alerts

#### Configure Azure Security
```bash
# Install Azure CLI
# Windows
winget install Microsoft.AzureCLI

# macOS
brew install azure-cli

# Linux
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

# Login to Azure
az login

# Set subscription
az account set --subscription "Your-Subscription-ID"
```

#### Create Resource Group for Lab
```bash
# Create lab resource group
az group create \
  --name "cloud-security-lab" \
  --location "eastus"

# Set default resource group
az configure --defaults group=cloud-security-lab
```

### 2. AWS Account Setup

#### Create AWS Account
1. Visit [AWS Console](https://console.aws.amazon.com)
2. Create free tier account
3. Complete identity verification
4. Set up billing alerts

#### Configure AWS Security
```bash
# Install AWS CLI
# Windows
winget install Amazon.AWSCLI

# macOS
brew install awscli

# Linux
sudo apt-get install awscli

# Configure AWS credentials
aws configure
# AWS Access Key ID: YOUR_ACCESS_KEY
# AWS Secret Access Key: YOUR_SECRET_KEY
# Default region name: us-east-1
# Default output format: json
```

#### Create IAM User for Lab
```bash
# Create IAM user with programmatic access
aws iam create-user --user-name lab-user

# Create policy with limited permissions
cat > lab-policy.json << EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:*",
                "s3:*",
                "vpc:*",
                "iam:*",
                "cloudwatch:*",
                "logs:*"
            ],
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "aws:RequestedRegion": ["us-east-1"]
                }
            }
        }
    ]
}
EOF

aws iam create-policy --policy-name LabPolicy --policy-document file://lab-policy.json
aws iam attach-user-policy --user-name lab-user --policy-arn arn:aws:iam::ACCOUNT:policy/LabPolicy
```

##  Local Development Environment

### 1. Install Essential Tools

#### Git and Version Control
```bash
# Install Git
# Windows
winget install Git.Git

# macOS
brew install git

# Linux
sudo apt-get install git

# Configure Git
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"
```

#### Visual Studio Code
```bash
# Install VS Code
# Windows
winget install Microsoft.VisualStudioCode

# macOS
brew install --cask visual-studio-code

# Linux
wget -qO- https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > packages.microsoft.gpg
sudo install -o root -g root -m 644 packages.microsoft.gpg /etc/apt/trusted.gpg.d/
```

#### Docker and Containers
```bash
# Install Docker Desktop
# Download from https://www.docker.com/products/docker-desktop

# Verify installation
docker --version
docker-compose --version
```

#### Terraform for Infrastructure as Code
```bash
# Install Terraform
# Windows
winget install Hashicorp.Terraform

# macOS
brew install terraform

# Linux
wget https://releases.hashicorp.com/terraform/1.6.0/terraform_1.6.0_linux_amd64.zip
unzip terraform_1.6.0_linux_amd64.zip
sudo mv terraform /usr/local/bin/

# Verify installation
terraform --version
```

### 2. Security Tools Installation

#### Kali Linux (Optional but Recommended)
```bash
# Using WSL on Windows
wsl --install -d kali-linux

# Using Docker
docker run -it kalilinux/kali-rolling /bin/bash

# Update and install security tools
apt update && apt upgrade -y
apt install -y nmap metasploit-framework wireshark burpsuite
```

#### Cloud Security Tools
```bash
# Install Prowler (AWS security scanning)
pip install prowler

# Install ScoutSuite (multi-cloud security)
pip install scoutsuite

# Install CloudSploit (cloud security scanning)
npm install -g @cloudsploit/scanner

# Install Azure CLI extensions
az extension add --name azure-security
```

##  Lab Infrastructure Setup

### 1. Azure Lab Environment

#### Create Virtual Network
```bash
# Create VNet
az network vnet create \
  --resource-group cloud-security-lab \
  --name lab-vnet \
  --address-prefix 10.0.0.0/16 \
  --subnet-name lab-subnet \
  --subnet-prefix 10.0.1.0/24

# Create Network Security Group
az network nsg create \
  --resource-group cloud-security-lab \
  --name lab-nsg

# Allow SSH and RDP access
az network nsg rule create \
  --resource-group cloud-security-lab \
  --nsg-name lab-nsg \
  --name allow-ssh \
  --protocol tcp \
  --direction inbound \
  --priority 1000 \
  --source-address-prefix "*" \
  --source-port-range "*" \
  --destination-address-prefix "*" \
  --destination-port-range 22 \
  --access allow

az network nsg rule create \
  --resource-group cloud-security-lab \
  --nsg-name lab-nsg \
  --name allow-rdp \
  --protocol tcp \
  --direction inbound \
  --priority 1001 \
  --source-address-prefix "*" \
  --source-port-range "*" \
  --destination-address-prefix "*" \
  --destination-port-range 3389 \
  --access allow
```

#### Create Test Virtual Machine
```bash
# Create Ubuntu VM
az vm create \
  --resource-group cloud-security-lab \
  --name lab-vm-ubuntu \
  --image UbuntuLTS \
  --vnet-name lab-vnet \
  --subnet lab-subnet \
  --nsg lab-nsg \
  --admin-username labuser \
  --generate-ssh-keys \
  --size Standard_B1s

# Create Windows VM
az vm create \
  --resource-group cloud-security-lab \
  --name lab-vm-windows \
  --image Win2019Datacenter \
  --vnet-name lab-vnet \
  --subnet lab-subnet \
  --nsg lab-nsg \
  --admin-username labuser \
  --admin-password YourSecurePassword123! \
  --size Standard_B1s
```

### 2. AWS Lab Environment

#### Create VPC and Subnets
```bash
# Create VPC
aws ec2 create-vpc --cidr-block 10.0.0.0/16 --tag-specifications 'ResourceType=vpc,Tags=[{Key=Name,Value=lab-vpc}]'

# Create subnets
aws ec2 create-subnet --vpc-id vpc-xxxxxxxxx --cidr-block 10.0.1.0/24 --availability-zone us-east-1a
aws ec2 create-subnet --vpc-id vpc-xxxxxxxxx --cidr-block 10.0.2.0/24 --availability-zone us-east-1b

# Create internet gateway
aws ec2 create-internet-gateway --tag-specifications 'ResourceType=internet-gateway,Tags=[{Key=Name,Value=lab-igw}]'
aws ec2 attach-internet-gateway --vpc-id vpc-xxxxxxxxx --internet-gateway-id igw-xxxxxxxxx
```

#### Create Security Groups
```bash
# Create security group
aws ec2 create-security-group --group-name lab-sg --description "Lab security group" --vpc-id vpc-xxxxxxxxx

# Add rules for SSH and RDP
aws ec2 authorize-security-group-ingress --group-id sg-xxxxxxxxx --protocol tcp --port 22 --cidr 0.0.0.0/0
aws ec2 authorize-security-group-ingress --group-id sg-xxxxxxxxx --protocol tcp --port 3389 --cidr 0.0.0.0/0
```

#### Launch EC2 Instances
```bash
# Launch Ubuntu instance
aws ec2 run-instances \
  --image-id ami-0c02fb55956c7d316 \
  --instance-type t2.micro \
  --key-name your-key-pair \
  --security-group-ids sg-xxxxxxxxx \
  --subnet-id subnet-xxxxxxxxx \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=lab-ubuntu}]'

# Launch Windows instance
aws ec2 run-instances \
  --image-id ami-0abcdef1234567890 \
  --instance-type t2.micro \
  --key-name your-key-pair \
  --security-group-ids sg-xxxxxxxxx \
  --subnet-id subnet-xxxxxxxxx \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=lab-windows}]'
```

##  Monitoring and Logging Setup

### 1. Azure Monitoring
```bash
# Create Log Analytics workspace
az monitor log-analytics workspace create \
  --resource-group cloud-security-lab \
  --workspace-name lab-law

# Enable VM monitoring
az monitor diagnostics set \
  --resource lab-vm-ubuntu \
  --resource-group cloud-security-lab \
  --workspace lab-law \
  --metrics 'AllMetrics'

# Create Azure Monitor alerts
az monitor metrics alert create \
  --name "High CPU Alert" \
  --resource-group cloud-security-lab \
  --scopes "/subscriptions/SUBSCRIPTION_ID/resourceGroups/cloud-security-lab/providers/Microsoft.Compute/virtualMachines/lab-vm-ubuntu" \
  --condition "avg PercentageCPU > 80" \
  --window-size 5m \
  --evaluation-frequency 1m \
  --severity 2
```

### 2. AWS CloudWatch
```bash
# Create CloudWatch alarm for CPU utilization
aws cloudwatch put-metric-alarm \
  --alarm-name "High-CPU-Utilization" \
  --alarm-description "Alarm when CPU exceeds 80%" \
  --metric-name CPUUtilization \
  --namespace AWS/EC2 \
  --statistic Average \
  --period 300 \
  --threshold 80 \
  --comparison-operator GreaterThanThreshold \
  --evaluation-periods 2

# Create log group
aws logs create-log-group --log-group-name /aws/ec2/lab-instances
```

##  Cost Management

### 1. Azure Cost Management
```bash
# Set up budget alerts
az consumption budget create \
  --resource-group cloud-security-lab \
  --name "Monthly-Budget" \
  --category cost \
  --amount 50 \
  --time-grain Monthly \
  --start-date 2024-01-01T00:00:00Z \
  --end-date 2024-12-31T23:59:59Z

# Enable cost alerts
az monitor metrics alert create \
  --name "Cost Alert" \
  --resource-group cloud-security-lab \
  --scopes "/subscriptions/SUBSCRIPTION_ID" \
  --condition "max Microsoft.CostManagement/costManagement/ActualCost > 40" \
  --window-size 1d \
  --evaluation-frequency 1d \
  --severity 3
```

### 2. AWS Budgets
```bash
# Create budget
aws budgets create-budget \
  --account-id YOUR_ACCOUNT_ID \
  --budget '{
    "BudgetName": "Monthly-Lab-Budget",
    "BudgetType": "COST",
    "TimeUnit": "MONTHLY",
    "BudgetLimit": {
      "Amount": "50",
      "Unit": "USD"
    },
    "CostFilters": {
      "Service": ["Amazon EC2", "Amazon S3"]
    }
  }' \
  --notifications-with-subscribers '[{
    "Notification": {
      "NotificationType": "ACTUAL",
      "ComparisonOperator": "GREATER_THAN",
      "Threshold": 80
    },
    "Subscribers": [{
      "SubscriptionType": "EMAIL",
      "Address": "your.email@example.com"
    }]
  }]'
```

##  Lab Security Hardening

### 1. Network Security
- Use private subnets where possible
- Implement network segmentation
- Configure firewall rules properly
- Use VPN for remote access

### 2. Access Management
- Implement MFA for all accounts
- Use least privilege access
- Regular access reviews
- Audit trail for all activities

### 3. Data Protection
- Encrypt data at rest and in transit
- Use secure key management
- Regular backup testing
- Data classification policies

##  Lab Validation Checklist

### Environment Setup
- [ ] Azure account configured with proper permissions
- [ ] AWS account configured with IAM user
- [ ] Local development environment ready
- [ ] Security tools installed and configured

### Infrastructure Deployment
- [ ] Azure VNet and VMs deployed
- [ ] AWS VPC and EC2 instances launched
- [ ] Network security groups configured
- [ ] Monitoring and logging enabled

### Cost Controls
- [ ] Budget alerts configured
- [ ] Resource tagging implemented
- [ ] Cost monitoring dashboard created
- [ ] Automated cleanup procedures documented

##  Next Steps

With your lab environment ready, you can now:

1. **[Learn Essential Tools](tools.md)** - Master security tools and utilities
2. **[Complete Your First Lab](first-lab.md)** - Apply your knowledge hands-on
3. **[Explore Core Security Areas](../core/)** - Deep dive into specific domains

##  Important Reminders

- **Never** store production credentials in your lab
- **Always** use strong, unique passwords
- **Regularly** review and clean up resources
- **Monitor** your cloud spending daily
- **Document** your lab configurations

---

** Your cloud security lab is now ready!** Start exploring security concepts in a safe, controlled environment.
