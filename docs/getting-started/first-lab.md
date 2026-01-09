#  Your First Cloud Security Lab

##  Overview

Welcome to your first hands-on cloud security lab! In this exercise, you'll deploy a secure web application infrastructure, identify security misconfigurations, and implement security best practices. This lab combines everything you've learned about tools, environments, and security fundamentals.

##  Learning Objectives

By completing this lab, you will:
- Deploy a multi-tier web application securely
- Identify and fix common security misconfigurations
- Implement network security controls
- Set up monitoring and alerting
- Practice security incident response

##  Lab Scenario

You're a cloud security engineer tasked with deploying a secure web application for a fictional company called "SecureShop". The application consists of:

- **Web Frontend**: Nginx web server
- **Application Backend**: Node.js API server
- **Database**: PostgreSQL database
- **Storage**: Object storage for static files
- **Monitoring**: Logging and metrics collection

##  Time Estimate

- **Total Duration**: 2-3 hours
- **Deployment**: 45 minutes
- **Security Assessment**: 60 minutes
- **Remediation**: 45 minutes
- **Testing & Validation**: 30 minutes

##  Prerequisites

Before starting this lab, ensure you have:
-  Completed [Lab Setup](lab-setup.md)
-  Installed [Essential Tools](tools.md)
-  Azure and AWS accounts configured
-  Basic understanding of cloud concepts

##  Step 1: Deploy the Infrastructure

### 1.1 Create the Project Structure
```bash
mkdir ~/first-security-lab
cd ~/first-security-lab

# Create directory structure
mkdir -p terraform/{azure,aws}
mkdir -p scripts
mkdir -p configs
mkdir -p documentation
```

### 1.2 Azure Infrastructure Deployment

#### Create Terraform Configuration
```hcl
# terraform/azure/main.tf
terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
}

provider "azurerm" {
  features {}
}

# Resource Group
resource "azurerm_resource_group" "main" {
  name     = "secure-shop-rg"
  location = "eastus"
}

# Virtual Network
resource "azurerm_virtual_network" "main" {
  name                = "secure-shop-vnet"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
}

# Subnets
resource "azurerm_subnet" "web" {
  name                 = "web-subnet"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.0.1.0/24"]
}

resource "azurerm_subnet" "app" {
  name                 = "app-subnet"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.0.2.0/24"]
}

resource "azurerm_subnet" "db" {
  name                 = "db-subnet"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.0.3.0/24"]
  delegation {
    name = "delegation"
    service_delegation {
      name    = "Microsoft.DBforPostgreSQL/flexibleServers"
      actions = ["Microsoft.Network/virtualNetworks/subnets/join/action", "Microsoft.Network/virtualNetworks/subnets/prepareNetworkPolicies/action"]
    }
  }
}

# Network Security Groups
resource "azurerm_network_security_group" "web" {
  name                = "web-nsg"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  security_rule {
    name                       = "allow-http"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "80"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "allow-https"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "allow-ssh"
    priority                   = 120
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "0.0.0.0/0"  #  SECURITY ISSUE: Too open!
    destination_address_prefix = "*"
  }
}

resource "azurerm_network_security_group" "app" {
  name                = "app-nsg"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  security_rule {
    name                       = "allow-web-to-app"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3000"
    source_address_prefix      = "10.0.1.0/24"
    destination_address_prefix = "*"
  }
}

# Public IP for Web Server
resource "azurerm_public_ip" "web" {
  name                = "web-pip"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  allocation_method   = "Static"
  sku                = "Standard"
}

# Network Interface
resource "azurerm_network_interface" "web" {
  name                = "web-nic"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.web.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.web.id
  }
}

# Virtual Machine
resource "azurerm_linux_virtual_machine" "web" {
  name                  = "web-vm"
  location              = azurerm_resource_group.main.location
  resource_group_name   = azurerm_resource_group.main.name
  network_interface_ids = [azurerm_network_interface.web.id]
  size                  = "Standard_B1s"

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "UbuntuServer"
    sku       = "18.04-LTS"
    version   = "latest"
  }

  admin_ssh_key {
    username   = "adminuser"
    public_key = file("~/.ssh/id_rsa.pub")
  }

  custom_data = base64encode(templatefile("${path.module}/web-init.sh", {
    db_password = var.db_password
  }))
}

# Storage Account
resource "azurerm_storage_account" "main" {
  name                     = "secureshopstorage${random_string.suffix.result}"
  resource_group_name      = azurerm_resource_group.main.name
  location                 = azurerm_resource_group.main.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  #  SECURITY ISSUE: Allow public access
  allow_blob_public_access = true
}

# Storage Container
resource "azurerm_storage_container" "static" {
  name                  = "static"
  storage_account_name  = azurerm_storage_account.main.name
  container_access_type = "container"  #  SECURITY ISSUE: Public container
}

# Variables
variable "db_password" {
  description = "Database password"
  type        = string
  sensitive   = true
}

resource "random_string" "suffix" {
  length  = 8
  special = false
  upper   = false
}

# Output
output "web_public_ip" {
  value = azurerm_public_ip.web.ip_address
}

output "storage_account_name" {
  value = azurerm_storage_account.main.name
}
```

#### Create Web Server Initialization Script
```bash
# terraform/azure/web-init.sh
#!/bin/bash
apt-get update
apt-get install -y nginx nodejs npm postgresql-client

# Create simple web application
cat > /var/www/html/index.html << EOF
<!DOCTYPE html>
<html>
<head>
    <title>SecureShop</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { background: #0078d4; color: white; padding: 20px; text-align: center; }
        .content { margin: 20px 0; }
        .warning { background: #ffebee; border: 1px solid #f44336; padding: 10px; margin: 10px 0; }
    </style>
</head>
<body>
    <div class="header">
        <h1> SecureShop</h1>
        <p>Your Secure E-commerce Platform</p>
    </div>
    <div class="content">
        <h2>Welcome to SecureShop!</h2>
        <p>This is a demo application for cloud security learning.</p>
        <div class="warning">
            <strong>⚠️ Security Notice:</strong> This application contains intentional security vulnerabilities for educational purposes.
        </div>
        <h3>Features:</h3>
        <ul>
            <li>Secure user authentication</li>
            <li>Encrypted data storage</li>
            <li>Real-time monitoring</li>
            <li>Compliance reporting</li>
        </ul>
    </div>
</body>
</html>
EOF

# Start nginx
systemctl start nginx
systemctl enable nginx

# Create simple API server
cat > /home/adminuser/app.js << EOF
const express = require('express');
const app = express();
const port = 3000;

app.get('/api/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

app.get('/api/users', (req, res) => {
  //  SECURITY ISSUE: No authentication required
  res.json([
    { id: 1, name: 'Admin User', email: 'admin@secureshop.com', role: 'admin' },
    { id: 2, name: 'Test User', email: 'test@secureshop.com', role: 'user' }
  ]);
});

app.listen(port, '0.0.0.0', () => {
  console.log(`API server running on port ${port}`);
});
EOF

cd /home/adminuser
npm init -y
npm install express
nohup node app.js &

# Create configuration file with sensitive data
cat > /home/adminuser/config.json << EOF
{
  "database": {
    "host": "localhost",
    "port": 5432,
    "name": "secureshop",
    "username": "admin",
    "password": "${db_password}"
  },
  "api_keys": {
    "payment_gateway": "sk_test_1234567890abcdef",
    "email_service": "SG.1234567890abcdef"
  }
}
EOF

chmod 644 /home/adminuser/config.json  #  SECURITY ISSUE: World-readable
```

#### Create Variables File
```hcl
# terraform/azure/terraform.tfvars
db_password = "InsecurePassword123!"  #  SECURITY ISSUE: Weak password
```

### 1.3 Deploy the Infrastructure
```bash
cd terraform/azure

# Initialize Terraform
terraform init

# Plan the deployment
terraform plan -var-file="terraform.tfvars"

# Deploy the infrastructure
terraform apply -var-file="terraform.tfvars" -auto-approve

# Note the outputs
terraform output
```

## 🔍 Step 2: Security Assessment

Now that the infrastructure is deployed, let's identify security issues using various tools.

### 2.1 Infrastructure Scanning
```bash
# Scan with Checkov
cd ~/first-security-lab
checkov -d terraform/azure --framework terraform

# Expected findings:
# - CKV_AZURE_1: Ensure that Network Security Group allows SSH access from specific IP addresses
# - CKV_AZURE_2: Ensure that Storage Accounts disallow public access
# - CKV_AZURE_3: Ensure that Storage container access level is set to private
# - CKV_AZURE_4: Ensure that VM disks are encrypted
```

### 2.2 Cloud Platform Security Assessment
```bash
# Azure Security Assessment with Prowler
prowler azure -M csv,html

# Manual Azure CLI checks
az network nsg list --resource-group secure-shop-rg --output table
az storage account list --resource-group secure-shop-rg --output table
az vm list --resource-group secure-shop-rg --output table

# Check for public IPs
az network public-ip list --resource-group secure-shop-rg --output table
```

### 2.3 Application Security Testing
```bash
# Get the web server public IP
WEB_IP=$(terraform output -raw web_public_ip)

# Test web application
curl http://$WEB_IP

# Test API endpoints
curl http://$WEB_IP:3000/api/health
curl http://$WEB_IP:3000/api/users  #  Should not be accessible without authentication

# Port scanning with nmap
nmap -sS -sV -O $WEB_IP

# Check for open ports and services
```

### 2.4 Configuration Review
```bash
# SSH into the web server
ssh adminuser@$WEB_IP

# Check file permissions
ls -la /home/adminuser/config.json  #  Should not be world-readable

# Check running processes
ps aux | grep node

# Check network connections
netstat -tlnp

# Check system logs for security events
sudo tail -f /var/log/auth.log
```

##  Step 3: Security Remediation

Now let's fix the security issues we identified.

### 3.1 Fix Infrastructure Security Issues

#### Update Terraform Configuration
```hcl
# terraform/azure/main.tf (updated sections)

# Fix Network Security Group
resource "azurerm_network_security_group" "web" {
  name                = "web-nsg"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  security_rule {
    name                       = "allow-http"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "80"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "allow-https"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  #  FIXED: Restrict SSH access to specific IP
  security_rule {
    name                       = "allow-ssh"
    priority                   = 120
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "YOUR_HOME_IP/32"  # Replace with your IP
    destination_address_prefix = "*"
  }

  #  ADDED: Deny all other inbound traffic
  security_rule {
    name                       = "deny-all-inbound"
    priority                   = 4096
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

#  FIXED: Secure Storage Account
resource "azurerm_storage_account" "main" {
  name                     = "secureshopstorage${random_string.suffix.result}"
  resource_group_name      = azurerm_resource_group.main.name
  location                 = azurerm_resource_group.main.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  min_tls_version          = "TLS1_2"
  
  #  FIXED: Disable public access
  allow_blob_public_access = false
  
  #  ADDED: Enable encryption
  infrastructure_encryption_enabled = true
  
  #  ADDED: Network rules
  network_rules {
    default_action = "Deny"
    bypass         = ["AzureServices"]
  }
}

#  FIXED: Private Storage Container
resource "azurerm_storage_container" "static" {
  name                  = "static"
  storage_account_name  = azurerm_storage_account.main.name
  container_access_type = "private"  #  FIXED: Private container
}

#  ADDED: VM Disk Encryption
resource "azurerm_virtual_machine_extension" "encryption" {
  name                 = "encryption"
  virtual_machine_id   = azurerm_linux_virtual_machine.web.id
  publisher            = "Microsoft.Azure.Security"
  type                 = "AzureDiskEncryptionForLinux"
  type_handler_version = "1.1"
  
  settings = jsonencode({
    EncryptionOperation = "EnableEncryption"
    KeyVaultURL        = azurerm_key_vault.main.vault_uri
    KeyVaultResourceId = azurerm_key_vault.main.id
    KekVaultResourceId = azurerm_key_vault.main.id
    KeyEncryptionKeyURL = azurerm_key_vault_key.main.id
  })
}

#  ADDED: Key Vault for Secrets
resource "azurerm_key_vault" "main" {
  name                = "secureshop-kv-${random_string.suffix.result}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  tenant_id           = data.azurerm_client_config.current.tenant_id
  sku_name            = "standard"

  access_policy {
    tenant_id = data.azurerm_client_config.current.tenant_id
    object_id = data.azurerm_client_config.current.object_id

    key_permissions = [
      "Get", "List", "Create", "Delete", "Update"
    ]

    secret_permissions = [
      "Get", "List", "Set", "Delete"
    ]
  }
}

resource "azurerm_key_vault_secret" "db_password" {
  name         = "db-password"
  value        = var.db_password
  key_vault_id = azurerm_key_vault.main.id
}

data "azurerm_client_config" "current {}
```

#### Update Variables File
```hcl
# terraform/azure/terraform.tfvars (updated)
db_password = "SecureComplexPassword!@#$2024"  #  FIXED: Strong password
```

### 3.2 Fix Application Security Issues

#### Update Web Server Configuration
```bash
# terraform/azure/web-init.sh (updated sections)

#  FIXED: Secure configuration file permissions
chmod 600 /home/adminuser/config.json

#  ADDED: Secure Nginx configuration
cat > /etc/nginx/sites-available/secureshop << EOF
server {
    listen 80;
    server_name _;
    
    #  ADDED: Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'" always;
    
    #  ADDED: Hide server version
    server_tokens off;
    
    root /var/www/html;
    index index.html;
    
    location / {
        try_files \$uri \$uri/ =404;
    }
    
    #  ADDED: Block access to sensitive files
    location ~ /\. {
        deny all;
    }
    
    location ~ \.(conf|log|sql|json)$ {
        deny all;
    }
}
EOF

ln -s /etc/nginx/sites-available/secureshop /etc/nginx/sites-enabled/
rm /etc/nginx/sites-enabled/default

#  ADDED: Configure firewall
ufw --force enable
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw deny 3000/tcp  # Block direct API access

#  FIXED: Secure API server
cat > /home/adminuser/app.js << EOF
const express = require('express');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const app = express();
const port = 3000;

//  ADDED: Security middleware
app.use(helmet());
app.use(express.json({ limit: '10mb' }));

//  ADDED: Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

//  ADDED: Simple authentication middleware
const authenticate = (req, res, next) => {
  const token = req.headers.authorization;
  if (token === 'Bearer secure-token-123') {
    next();
  } else {
    res.status(401).json({ error: 'Unauthorized' });
  }
};

app.get('/api/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

//  FIXED: Protected endpoint
app.get('/api/users', authenticate, (req, res) => {
  res.json([
    { id: 1, name: 'Admin User', email: 'admin@secureshop.com', role: 'admin' },
    { id: 2, name: 'Test User', email: 'test@secureshop.com', role: 'user' }
  ]);
});

app.listen(port, '127.0.0.1', () => {  //  FIXED: Listen on localhost only
  console.log(\`API server running on port \${port}\`);
});
EOF

# Install security packages
npm install helmet express-rate-limit

# Restart services
systemctl restart nginx
pkill node
cd /home/adminuser
nohup node app.js &
```

### 3.3 Apply Security Fixes
```bash
cd terraform/azure

# Apply the updated configuration
terraform plan -var-file="terraform.tfvars"
terraform apply -var-file="terraform.tfvars" -auto-approve

# Re-run security scans to verify fixes
checkov -d . --framework terraform
```

##  Step 4: Monitoring and Alerting

### 4.1 Set Up Azure Monitor
```bash
# Create Log Analytics Workspace
az monitor log-analytics workspace create \
  --resource-group secure-shop-rg \
  --workspace-name secure-shop-law

# Enable VM monitoring
az monitor diagnostics set \
  --resource $(az vm show -g secure-shop-rg -n web-vm --query id -o tsv) \
  --workspace secure-shop-law \
  --metrics 'AllMetrics'

# Create security alerts
az monitor metrics alert create \
  --resource-group secure-shop-rg \
  --name "Failed SSH Attempts" \
  --scopes "/subscriptions/$(az account show --query id -o tsv)/resourceGroups/secure-shop-rg/providers/Microsoft.Compute/virtualMachines/web-vm" \
  --condition "avg Microsoft.Compute/virtualMachines/NetworkIn > 1000" \
  --window-size 5m \
  --evaluation-frequency 1m \
  --severity 2
```

### 4.2 Create Security Dashboard
```bash
# Create Azure Dashboard (JSON configuration)
cat > security-dashboard.json << EOF
{
  "properties": {
    "lenses": [
      {
        "order": 0,
        "parts": [
          {
            "position": {
              "x": 0,
              "y": 0,
              "colSpan": 6,
              "rowSpan": 4
            },
            "metadata": {
              "type": "Extension/Microsoft_Azure_Monitoring/PartType/MetricsChartPart",
              "inputs": [
                {
                  "name": "metrics",
                  "value": {
                    "resourceId": "/subscriptions/$(az account show --query id -o tsv)/resourceGroups/secure-shop-rg/providers/Microsoft.Compute/virtualMachines/web-vm",
                    "metrics": [
                      {
                        "name": "Network In",
                        "aggregation": "Total"
                      }
                    ]
                  }
                }
              ]
            }
          }
        ]
      }
    ]
  }
}
EOF

# Deploy dashboard
az portal dashboard create \
  --resource-group secure-shop-rg \
  --name "Security Dashboard" \
  --input-path security-dashboard.json
```

##  Step 5: Security Testing

### 5.1 Post-Remediation Testing
```bash
# Test web application
WEB_IP=$(terraform output -raw web_public_ip)
curl -I http://$WEB_IP

# Verify security headers
curl -I http://$WEB_IP | grep -E "(X-Frame-Options|X-Content-Type-Options|X-XSS-Protection)"

# Test API with authentication
curl -H "Authorization: Bearer secure-token-123" http://$WEB_IP:3000/api/users

# Test API without authentication (should fail)
curl -i http://$WEB_IP:3000/api/users

# Port scanning (should show fewer open ports)
nmap -sS -sV $WEB_IP
```

### 5.2 Automated Security Testing
```bash
# Create automated security test script
cat > scripts/security-test.sh << EOF
#!/bin/bash

WEB_IP=\$1
echo "Testing security for \$WEB_IP"

# Test 1: Check for security headers
echo "=== Testing Security Headers ==="
curl -s -I http://\$WEB_IP | grep -E "(X-Frame-Options|X-Content-Type-Options|X-XSS-Protection|Content-Security-Policy)"

# Test 2: Check for open ports
echo "=== Testing Open Ports ==="
nmap -sS -p 22,80,443,3000 \$WEB_IP

# Test 3: Test API authentication
echo "=== Testing API Authentication ==="
echo "Without auth:"
curl -s -o /dev/null -w "%{http_code}" http://\$WEB_IP:3000/api/users
echo ""
echo "With auth:"
curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer secure-token-123" http://\$WEB_IP:3000/api/users
echo ""

# Test 4: Check for sensitive files
echo "=== Testing for Sensitive Files ===
curl -s -o /dev/null -w "%{http_code}" http://\$WEB_IP/config.json
curl -s -o /dev/null -w "%{http_code}" http://\$WEB_IP/.env
echo ""

echo "Security testing completed."
EOF

chmod +x scripts/security-test.sh

# Run the security test
./scripts/security-test.sh $WEB_IP
```

##  Step 6: Documentation and Cleanup

### 6.1 Document Your Findings
```bash
# Create lab report
cat > documentation/lab-report.md << EOF
# Cloud Security Lab Report

## Infrastructure Overview
- **Resource Group**: secure-shop-rg
- **Web Server**: $(terraform output -raw web_public_ip)
- **Storage Account**: $(terraform output -raw storage_account_name)

## Security Issues Found and Fixed

### 1. Network Security
- **Issue**: SSH access open to all IPs
- **Fix**: Restricted to specific IP addresses
- **Status**:  Resolved

### 2. Storage Security
- **Issue**: Public blob access enabled
- **Fix**: Disabled public access, made containers private
- **Status**:  Resolved

### 3. Application Security
- **Issue**: No authentication on API endpoints
- **Fix**: Added authentication middleware
- **Status**:  Resolved

### 4. Configuration Security
- **Issue**: Weak passwords and world-readable config files
- **Fix**: Strong passwords and proper file permissions
- **Status**:  Resolved

## Security Test Results
$(./scripts/security-test.sh $(terraform output -raw web_public_ip))

## Lessons Learned
1. Always implement least privilege access
2. Encrypt data at rest and in transit
3. Use strong authentication mechanisms
4. Regular security scanning is essential
5. Monitor and log security events

## Next Steps
1. Implement automated security scanning in CI/CD
2. Set up regular security assessments
3. Implement incident response procedures
4. Add compliance monitoring
EOF
```

### 6.2 Cleanup Resources
```bash
# IMPORTANT: Only run this when you're done with the lab!
# cd terraform/azure
# terraform destroy -var-file="terraform.tfvars" -auto-approve
```

##  Lab Completion Checklist

### Infrastructure Deployment
- [ ] Azure resource group created
- [ ] Virtual network and subnets deployed
- [ ] Network security groups configured
- [ ] Virtual machine deployed and configured
- [ ] Storage account and containers created

### Security Assessment
- [ ] Infrastructure scanned with Checkov
- [ ] Cloud security assessment completed
- [ ] Application security testing performed
- [ ] Configuration review conducted

### Security Remediation
- [ ] Network security issues fixed
- [ ] Storage security implemented
- [ ] Application security enhanced
- [ ] Configuration security improved

### Monitoring and Testing
- [ ] Monitoring and alerting configured
- [ ] Security dashboard created
- [ ] Post-remediation testing completed
- [ ] Automated security tests created

### Documentation
- [ ] Lab report created
- [ ] Findings documented
- [ ] Lessons learned recorded
- [ ] Next steps identified

##  Key Takeaways

1. **Defense in Depth**: Multiple layers of security are essential
2. **Least Privilege**: Always grant minimum necessary permissions
3. **Continuous Monitoring**: Security is an ongoing process
4. **Automation**: Automate security scanning and remediation
5. **Documentation**: Document configurations and decisions

##  Next Steps

Now that you've completed your first security lab:

1. **Explore Advanced Topics**: Learn about more complex security scenarios
2. **Build Your Own Labs**: Create security challenges for others
3. **Contribute to the Community**: Share your security patterns
4. **Stay Updated**: Keep learning about new security threats and defenses

---

** Congratulations!** You've successfully completed your first cloud security lab. You've deployed infrastructure, identified security issues, implemented fixes, and set up monitoring. This is just the beginning of your cloud security journey!
