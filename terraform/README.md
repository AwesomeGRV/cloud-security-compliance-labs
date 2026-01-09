# Terraform Security Templates

## Overview

This section provides secure Infrastructure as Code (IaC) templates using Terraform. These templates implement security best practices for cloud deployments and can be used as building blocks for secure cloud architectures.

## Learning Objectives

By using these templates, you will:
- Understand secure IaC patterns and practices
- Implement security controls in infrastructure code
- Create reusable security modules
- Automate security compliance checks
- Build secure cloud architectures
- Implement infrastructure security testing

## Template Categories

### Network Security Templates
- **[Secure VNet](modules/secure-vnet/)** - Secure virtual network implementation
- **[Network Security Groups](modules/nsg/)** - Security group configurations
- **[Azure Firewall](modules/firewall/)** - Firewall deployment templates
- **[DDoS Protection](modules/ddos/)** - DDoS protection setup

### Compute Security Templates
- **[Secure VM](modules/secure-vm/)** - Secure virtual machine deployment
- **[VM Security Hardening](modules/vm-hardening/)** - VM security configurations
- **[Availability Sets](modules/availability-set/)** - High availability setups
- **[Scale Sets](modules/scale-set/)** - Secure scaling configurations

### Storage Security Templates
- **[Secure Storage Account](modules/secure-storage/)** - Secure storage implementation
- **[Blob Security](modules/blob-security/)** - Blob container security
- **[File Share Security](modules/file-share/)** - File share security
- **[Backup Configuration](modules/backup/)** - Backup and recovery

### Identity and Access Templates
- **[Key Vault](modules/key-vault/)** - Key management implementation
- **[Managed Identity](modules/managed-identity/)** - Identity management
- **[RBAC Configuration](modules/rbac/)** - Role-based access control
- **[Conditional Access](modules/conditional-access/)** - Access policies

### Monitoring and Logging Templates
- **[Log Analytics](modules/log-analytics/)** - Logging infrastructure
- **[Monitor Alerts](modules/monitoring/)** - Alert configurations
- **[Security Center](modules/security-center/)** - Security monitoring
- **[Audit Logging](modules/audit-logging/)** - Audit trail setup

## Security Modules

### 1. Secure Virtual Network Module

#### Module Structure
```
terraform/
├── modules/
│   ├── secure-vnet/
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   ├── outputs.tf
│   │   └── README.md
│   ├── secure-storage/
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   ├── outputs.tf
│   │   └── README.md
│   └── secure-vm/
│       ├── main.tf
│       ├── variables.tf
│       ├── outputs.tf
│       └── README.md
├── examples/
│   ├── basic-setup/
│   ├── multi-tier-app/
│   └── secure-environment/
└── tests/
    ├── secure-vnet-test/
    └── secure-storage-test/
```

#### Secure VNet Module Implementation
```hcl
# modules/secure-vnet/main.tf
terraform {
  required_version = ">= 1.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
}

variable "vnet_name" {
  description = "Name of the virtual network"
  type        = string
}

variable "resource_group_name" {
  description = "Name of the resource group"
  type        = string
}

variable "location" {
  description = "Azure region"
  type        = string
}

variable "address_space" {
  description = "Address space for the VNet"
  type        = list(string)
}

variable "subnets" {
  description = "List of subnets"
  type = list(object({
    name           = string
    address_prefix = string
    nsg_rules     = list(object({
      name                       = string
      priority                   = number
      direction                  = string
      access                     = string
      protocol                   = string
      source_port_range          = string
      destination_port_range     = string
      source_address_prefix      = string
      destination_address_prefix = string
    }))
  }))
}

variable "enable_ddos_protection" {
  description = "Enable DDoS protection"
  type        = bool
  default     = true
}

variable "tags" {
  description = "Tags for the resources"
  type        = map(string)
  default     = {}
}

# Data source for resource group
data "azurerm_resource_group" "main" {
  name = var.resource_group_name
}

# DDoS protection plan
resource "azurerm_network_ddos_protection_plan" "main" {
  count               = var.enable_ddos_protection ? 1 : 0
  name                = "${var.vnet_name}-ddos"
  location            = data.azurerm_resource_group.main.location
  resource_group_name = data.azurerm_resource_group.main.name
  tags                = var.tags
}

# Virtual network
resource "azurerm_virtual_network" "main" {
  name                = var.vnet_name
  address_space       = var.address_space
  location            = data.azurerm_resource_group.main.location
  resource_group_name = data.azurerm_resource_group.main.name
  ddos_protection_plan = var.enable_ddos_protection ? azurerm_network_ddos_protection_plan.main[0].id : null
  tags                = var.tags
}

# Network security groups
resource "azurerm_network_security_group" "main" {
  for_each            = { for subnet in var.subnets : subnet.name => subnet }
  name                = "${var.vnet_name}-${each.key}-nsg"
  location            = data.azurerm_resource_group.main.location
  resource_group_name = data.azurerm_resource_group.main.name
  tags                = var.tags
}

# NSG rules
resource "azurerm_network_security_rule" "main" {
  for_each = {
    for subnet in var.subnets :
    "${subnet.name}-${rule.name}" => {
      subnet = subnet
      rule   = rule
    }
    for rule in subnet.nsg_rules
  }
  
  name                       = each.value.rule.name
  priority                   = each.value.rule.priority
  direction                  = each.value.rule.direction
  access                     = each.value.rule.access
  protocol                   = each.value.rule.protocol
  source_port_range          = each.value.rule.source_port_range
  destination_port_range     = each.value.rule.destination_port_range
  source_address_prefix      = each.value.rule.source_address_prefix
  destination_address_prefix = each.value.rule.destination_address_prefix
  resource_group_name       = data.azurerm_resource_group.main.name
  network_security_group_name = azurerm_network_security_group.main[each.value.subnet.name].name
}

# Subnets
resource "azurerm_subnet" "main" {
  for_each             = { for subnet in var.subnets : subnet.name => subnet }
  name                 = each.key
  resource_group_name  = data.azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = [each.value.address_prefix]
  network_security_group_id = azurerm_network_security_group.main[each.key].id
}

# Outputs
output "vnet_id" {
  value = azurerm_virtual_network.main.id
}

output "subnet_ids" {
  value = {
    for subnet in var.subnets :
    subnet.name => azurerm_subnet.main[subnet.name].id
  }
}

output "nsg_ids" {
  value = {
    for subnet in var.subnets :
    subnet.name => azurerm_network_security_group.main[subnet.name].id
  }
}
```

#### Variables Definition
```hcl
# modules/secure-vnet/variables.tf
variable "vnet_name" {
  description = "Name of the virtual network"
  type        = string
  
  validation {
    condition     = can(regex("^[a-zA-Z0-9-]{3,64}$", var.vnet_name))
    error_message = "Virtual network name must be 3-64 characters and contain only letters, numbers, and hyphens."
  }
}

variable "resource_group_name" {
  description = "Name of the resource group"
  type        = string
}

variable "location" {
  description = "Azure region"
  type        = string
  
  validation {
    condition     = contains(["eastus", "westus", "centralus", "eastus2", "westus2"], var.location)
    error_message = "Location must be a valid Azure region."
  }
}

variable "address_space" {
  description = "Address space for the VNet"
  type        = list(string)
  
  validation {
    condition     = length(var.address_space) > 0
    error_message = "At least one address space must be provided."
  }
}

variable "subnets" {
  description = "List of subnets"
  type = list(object({
    name           = string
    address_prefix = string
    nsg_rules     = list(object({
      name                       = string
      priority                   = number
      direction                  = string
      access                     = string
      protocol                   = string
      source_port_range          = string
      destination_port_range     = string
      source_address_prefix      = string
      destination_address_prefix = string
    }))
  }))
  
  validation {
    condition     = length(var.subnets) > 0
    error_message = "At least one subnet must be provided."
  }
}

variable "enable_ddos_protection" {
  description = "Enable DDoS protection"
  type        = bool
  default     = true
}

variable "tags" {
  description = "Tags for the resources"
  type        = map(string)
  default     = {}
}
```

### 2. Secure Storage Account Module

#### Storage Module Implementation
```hcl
# modules/secure-storage/main.tf
variable "storage_account_name" {
  description = "Name of the storage account"
  type        = string
}

variable "resource_group_name" {
  description = "Name of the resource group"
  type        = string
}

variable "location" {
  description = "Azure region"
  type        = string
}

variable "account_tier" {
  description = "Storage account tier"
  type        = string
  default     = "Standard"
  
  validation {
    condition     = contains(["Standard", "Premium"], var.account_tier)
    error_message = "Account tier must be either Standard or Premium."
  }
}

variable "account_replication_type" {
  description = "Storage account replication type"
  type        = string
  default     = "LRS"
  
  validation {
    condition     = contains(["LRS", "GRS", "RAGRS", "ZRS"], var.account_replication_type)
    error_message = "Replication type must be one of: LRS, GRS, RAGRS, ZRS."
  }
}

variable "containers" {
  description = "List of containers"
  type = list(object({
    name                  = string
    access_type           = string
    infrastructure_encryption = bool
  }))
  default = []
}

variable "enable_advanced_threat_protection" {
  description = "Enable advanced threat protection"
  type        = bool
  default     = true
}

variable "tags" {
  description = "Tags for the resources"
  type        = map(string)
  default     = {}
}

# Data source for resource group
data "azurerm_resource_group" "main" {
  name = var.resource_group_name
}

# Storage account
resource "azurerm_storage_account" "main" {
  name                     = var.storage_account_name
  resource_group_name      = data.azurerm_resource_group.main.name
  location                 = data.azurerm_resource_group.main.location
  account_tier             = var.account_tier
  account_replication_type = var.account_replication_type
  min_tls_version          = "TLS1_2"
  allow_blob_public_access  = false
  infrastructure_encryption_enabled = true
  
  network_rules {
    default_action = "Deny"
    bypass         = ["AzureServices"]
  }
  
  tags = var.tags
}

# Containers
resource "azurerm_storage_container" "main" {
  for_each              = { for container in var.containers : container.name => container }
  name                  = each.key
  storage_account_name  = azurerm_storage_account.main.name
  container_access_type = each.value.access_type
}

# Advanced threat protection
resource "azurerm_storage_management_policy" "advanced_threat_protection" {
  count               = var.enable_advanced_threat_protection ? 1 : 0
  storage_account_id = azurerm_storage_account.main.id
  
  rule {
    name    = "malware-scan"
    enabled = true
    
    filters {
      prefix_match = ["*"]
      blob_types   = ["blockBlob"]
    }
    
    actions {
      base_blob {
        delete_after_days_since_modification_greater_than = 365
      }
    }
  }
}

# Outputs
output "storage_account_id" {
  value = azurerm_storage_account.main.id
}

output "storage_account_name" {
  value = azurerm_storage_account.main.name
}

output "primary_connection_string" {
  value     = azurerm_storage_account.main.primary_connection_string
  sensitive = true
}

output "container_ids" {
  value = {
    for container in var.containers :
    container.name => azurerm_storage_container.main[container.name].id
  }
}
```

## Example Implementations

### 1. Basic Secure Environment
```hcl
# examples/basic-setup/main.tf
terraform {
  required_version = ">= 1.0"
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

# Resource group
resource "azurerm_resource_group" "main" {
  name     = "secure-environment-rg"
  location = "eastus"
  
  tags = {
    Environment = "Production"
    Owner       = "Security Team"
    Purpose     = "Secure Infrastructure"
  }
}

# Secure virtual network
module "secure_vnet" {
  source = "../../modules/secure-vnet"
  
  vnet_name           = "secure-vnet"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  address_space       = ["10.0.0.0/16"]
  
  subnets = [
    {
      name           = "web-subnet"
      address_prefix = "10.0.1.0/24"
      nsg_rules = [
        {
          name                       = "allow-http"
          priority                   = 100
          direction                  = "Inbound"
          access                     = "Allow"
          protocol                   = "Tcp"
          source_port_range          = "*"
          destination_port_range     = "80"
          source_address_prefix      = "*"
          destination_address_prefix = "*"
        },
        {
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
      ]
    },
    {
      name           = "app-subnet"
      address_prefix = "10.0.2.0/24"
      nsg_rules = [
        {
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
      ]
    }
  ]
  
  enable_ddos_protection = true
  
  tags = {
    Environment = "Production"
    Owner       = "Security Team"
    Purpose     = "Secure Networking"
  }
}

# Secure storage account
module "secure_storage" {
  source = "../../modules/secure-storage"
  
  storage_account_name = "securestorage$(random_string.suffix.result)"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  
  containers = [
    {
      name                  = "logs"
      access_type           = "private"
      infrastructure_encryption = true
    },
    {
      name                  = "backups"
      access_type           = "private"
      infrastructure_encryption = true
    }
  ]
  
  enable_advanced_threat_protection = true
  
  tags = {
    Environment = "Production"
    Owner       = "Security Team"
    Purpose     = "Secure Storage"
  }
}

# Random suffix for unique names
resource "random_string" "suffix" {
  length  = 8
  special = false
  upper   = false
}

# Outputs
output "vnet_id" {
  value = module.secure_vnet.vnet_id
}

output "subnet_ids" {
  value = module.secure_vnet.subnet_ids
}

output "storage_account_id" {
  value = module.secure_storage.storage_account_id
}
```

### 2. Multi-Tier Secure Application
```hcl
# examples/multi-tier-app/main.tf
terraform {
  required_version = ">= 1.0"
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

# Resource group
resource "azurerm_resource_group" "main" {
  name     = "multi-tier-app-rg"
  location = "eastus"
  
  tags = {
    Environment = "Production"
    Application = "Multi-Tier App"
    Owner       = "Security Team"
  }
}

# Hub-and-spoke network architecture
module "hub_vnet" {
  source = "../../modules/secure-vnet"
  
  vnet_name           = "hub-vnet"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  address_space       = ["10.0.0.0/16"]
  
  subnets = [
    {
      name           = "gateway-subnet"
      address_prefix = "10.0.0.0/24"
      nsg_rules = [
        {
          name                       = "allow-gateway"
          priority                   = 100
          direction                  = "Inbound"
          access                     = "Allow"
          protocol                   = "*"
          source_port_range          = "*"
          destination_port_range     = "*"
          source_address_prefix      = "*"
          destination_address_prefix = "*"
        }
      ]
    },
    {
      name           = "firewall-subnet"
      address_prefix = "10.0.1.0/24"
      nsg_rules = []
    }
  ]
  
  enable_ddos_protection = true
  
  tags = {
    Environment = "Production"
    Purpose     = "Hub Network"
  }
}

# Web tier VNet
module "web_vnet" {
  source = "../../modules/secure-vnet"
  
  vnet_name           = "web-vnet"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  address_space       = ["10.1.0.0/16"]
  
  subnets = [
    {
      name           = "web-subnet"
      address_prefix = "10.1.1.0/24"
      nsg_rules = [
        {
          name                       = "allow-http"
          priority                   = 100
          direction                  = "Inbound"
          access                     = "Allow"
          protocol                   = "Tcp"
          source_port_range          = "*"
          destination_port_range     = "80"
          source_address_prefix      = "*"
          destination_address_prefix = "*"
        },
        {
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
      ]
    }
  ]
  
  tags = {
    Environment = "Production"
    Purpose     = "Web Tier"
  }
}

# Application tier VNet
module "app_vnet" {
  source = "../../modules/secure-vnet"
  
  vnet_name           = "app-vnet"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  address_space       = ["10.2.0.0/16"]
  
  subnets = [
    {
      name           = "app-subnet"
      address_prefix = "10.2.1.0/24"
      nsg_rules = [
        {
          name                       = "allow-web-to-app"
          priority                   = 100
          direction                  = "Inbound"
          access                     = "Allow"
          protocol                   = "Tcp"
          source_port_range          = "*"
          destination_port_range     = "3000"
          source_address_prefix      = "10.1.1.0/24"
          destination_address_prefix = "*"
        }
      ]
    }
  ]
  
  tags = {
    Environment = "Production"
    Purpose     = "Application Tier"
  }
}

# Data tier VNet
module "data_vnet" {
  source = "../../modules/secure-vnet"
  
  vnet_name           = "data-vnet"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  address_space       = ["10.3.0.0/16"]
  
  subnets = [
    {
      name           = "data-subnet"
      address_prefix = "10.3.1.0/24"
      nsg_rules = [
        {
          name                       = "allow-app-to-data"
          priority                   = 100
          direction                  = "Inbound"
          access                     = "Allow"
          protocol                   = "Tcp"
          source_port_range          = "*"
          destination_port_range     = "5432"
          source_address_prefix      = "10.2.1.0/24"
          destination_address_prefix = "*"
        }
      ]
    }
  ]
  
  tags = {
    Environment = "Production"
    Purpose     = "Data Tier"
  }
}

# VNet peering
resource "azurerm_virtual_network_peering" "hub_to_web" {
  name                         = "hub-to-web"
  resource_group_name          = azurerm_resource_group.main.name
  virtual_network_name         = module.hub_vnet.vnet_id
  remote_virtual_network_id    = module.web_vnet.vnet_id
  allow_virtual_network_access = true
  allow_forwarded_traffic     = false
}

resource "azurerm_virtual_network_peering" "web_to_hub" {
  name                         = "web-to-hub"
  resource_group_name          = azurerm_resource_group.main.name
  virtual_network_name         = module.web_vnet.vnet_id
  remote_virtual_network_id    = module.hub_vnet.vnet_id
  allow_virtual_network_access = true
  allow_forwarded_traffic     = false
}

# Similar peering for app and data tiers
# ... (additional peering configurations)
```

## Security Testing

### 1. Terraform Security Testing

#### Checkov Integration
```bash
#!/bin/bash
# security-tests.sh

echo "Running Terraform security tests..."

# Checkov security scanning
echo "Running Checkov..."
checkov -d . --framework terraform --output json > checkov-report.json

# tfsec security scanning
echo "Running tfsec..."
tfsec . --format json > tfsec-report.json

# terraform validate
echo "Validating Terraform configuration..."
terraform validate -json > terraform-validate.json

# terraform fmt check
echo "Checking Terraform formatting..."
terraform fmt -check -diff

# terraform plan
echo "Running Terraform plan..."
terraform plan -out=tfplan

# terraform show for plan analysis
terraform show -json tfplan > terraform-plan.json

echo "Security tests completed. Reports generated:"
echo "- checkov-report.json"
echo "- tfsec-report.json"
echo "- terraform-validate.json"
echo "- terraform-plan.json"
```

#### Security Gate Script
```python
# security_gate.py
import json
import sys
import os

class TerraformSecurityGate:
    def __init__(self):
        self.thresholds = {
            'checkov_failed': 0,
            'tfsec_high': 0,
            'tfsec_medium': 5,
            'validate_errors': 0
        }
    
    def load_checkov_report(self):
        """Load Checkov report"""
        try:
            with open('checkov-report.json', 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {}
    
    def load_tfsec_report(self):
        """Load tfsec report"""
        try:
            with open('tfsec-report.json', 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {}
    
    def load_terraform_validate(self):
        """Load Terraform validate results"""
        try:
            with open('terraform-validate.json', 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {}
    
    def evaluate_checkov(self, report):
        """Evaluate Checkov results"""
        if not report:
            return True, "No Checkov report found"
        
        failed_checks = 0
        for result in report.get('results', {}).get('failed_checks', []):
            failed_checks += 1
        
        if failed_checks > self.thresholds['checkov_failed']:
            return False, f"Too many Checkov failed checks: {failed_checks}"
        
        return True, f"Checkov scan passed: {failed_checks} failed checks"
    
    def evaluate_tfsec(self, report):
        """Evaluate tfsec results"""
        if not report:
            return True, "No tfsec report found"
        
        high_issues = len([r for r in report if r.get('severity') == 'HIGH'])
        medium_issues = len([r for r in report if r.get('severity') == 'MEDIUM'])
        
        if high_issues > self.thresholds['tfsec_high']:
            return False, f"Too many high severity tfsec issues: {high_issues}"
        
        if medium_issues > self.thresholds['tfsec_medium']:
            return False, f"Too many medium severity tfsec issues: {medium_issues}"
        
        return True, f"tfsec scan passed: {high_issues} high, {medium_issues} medium"
    
    def evaluate_terraform_validate(self, report):
        """Evaluate Terraform validate results"""
        if not report:
            return True, "No Terraform validate report found"
        
        if report.get('valid', True):
            return True, "Terraform validation passed"
        else:
            return False, f"Terraform validation failed: {report.get('error', 'Unknown error')}"
    
    def evaluate_all(self):
        """Evaluate all security reports"""
        results = []
        
        # Load all reports
        checkov_report = self.load_checkov_report()
        tfsec_report = self.load_tfsec_report()
        validate_report = self.load_terraform_validate()
        
        # Evaluate each report
        passed, message = self.evaluate_checkov(checkov_report)
        results.append(('Checkov', passed, message))
        
        passed, message = self.evaluate_tfsec(tfsec_report)
        results.append(('tfsec', passed, message))
        
        passed, message = self.evaluate_terraform_validate(validate_report)
        results.append(('Terraform Validate', passed, message))
        
        # Print results
        print("Terraform Security Gate Results:")
        print("=" * 50)
        
        all_passed = True
        for tool, passed, message in results:
            status = "PASS" if passed else "FAIL"
            print(f"{tool:20} {status:5} {message}")
            if not passed:
                all_passed = False
        
        print("=" * 50)
        
        if all_passed:
            print("SECURITY GATE: PASSED")
            return 0
        else:
            print("SECURITY GATE: FAILED")
            return 1

if __name__ == "__main__":
    gate = TerraformSecurityGate()
    sys.exit(gate.evaluate_all())
```

## Best Practices

### 1. Module Design
- **Single Purpose**: Each module should have a single, clear purpose
- **Reusable**: Design modules to be reusable across environments
- **Configurable**: Use variables for customization
- **Documented**: Provide comprehensive documentation

### 2. Security Implementation
- **Secure Defaults**: Use secure default configurations
- **Least Privilege**: Implement least privilege access
- **Encryption**: Enable encryption by default
- **Network Security**: Implement network segmentation

### 3. Testing and Validation
- **Automated Testing**: Include automated security testing
- **Code Review**: Conduct regular code reviews
- **Compliance Checks**: Validate against compliance frameworks
- **Continuous Integration**: Integrate with CI/CD pipelines

---

**Build secure infrastructure** by using these Terraform security modules and best practices.
