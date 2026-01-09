#  Azure Network Security

##  Overview

Azure Network Security provides comprehensive protection for your cloud infrastructure through layered security controls, network segmentation, and advanced threat protection. This guide covers essential network security concepts and hands-on implementations.

##  Learning Objectives

By completing this module, you will master:
- Network Security Groups (NSGs) and rule management
- Azure Firewall configuration and policies
- Virtual Network (VNet) design and segmentation
- DDoS protection implementation
- Application Gateway and WAF configuration
- Network monitoring and threat detection

##  Azure Network Security Architecture

### Core Components
```
                    Internet
                        │
                ┌─────────────┐
                │ Azure Firewall │
                │ (WAF + Threat) │
                └─────────────┘
                        │
                ┌─────────────────┐
                │   Hub VNet      │
                │ (DMZ/Security) │
                └─────────────────┘
                        │
        ┌───────────────┼───────────────┐
        │               │               │
   ┌──────────┐   ┌──────────┐   ┌──────────┐
   │ Web VNet │   │ App VNet │   │ Data VNet│
   │ (Web Tier)│  │ (App Tier)│  │ (Data Tier)│
   └──────────┘   └──────────┘   └──────────┘
        │               │               │
   ┌──────────┐   ┌──────────┐   ┌──────────┐
   │ NSGs     │   │ NSGs     │   │ NSGs     │
   │ Rules    │   │ Rules    │   │ Rules    │
   └──────────┘   └──────────┘   └──────────┘
```

##  Network Security Groups (NSGs)

### Understanding NSGs
Network Security Groups are stateful firewalls that filter network traffic between Azure resources in subnets and network interfaces.

#### NSG Rule Processing
1. **Inbound Rules**: Processed in priority order (lowest to highest)
2. **Outbound Rules**: Processed in priority order (lowest to highest)
3. **Default Rules**: Applied if no custom rules match
4. **Stateful**: Return traffic automatically allowed

### Hands-On Lab: NSG Configuration

#### Lab 1: Basic NSG Setup
```bash
# Create resource group
az group create --name network-security-lab --location eastus

# Create virtual network
az network vnet create \
  --resource-group network-security-lab \
  --name lab-vnet \
  --address-prefixes 10.0.0.0/16 \
  --subnet-name web-subnet \
  --subnet-prefix 10.0.1.0/24

# Create Network Security Group
az network nsg create \
  --resource-group network-security-lab \
  --name web-nsg

# Create NSG Rules
az network nsg rule create \
  --resource-group network-security-lab \
  --nsg-name web-nsg \
  --name allow-http \
  --protocol Tcp \
  --direction Inbound \
  --priority 100 \
  --source-address-prefix '*' \
  --source-port-range '*' \
  --destination-address-prefix '*' \
  --destination-port-range 80 \
  --access Allow

az network nsg rule create \
  --resource-group network-security-lab \
  --nsg-name web-nsg \
  --name allow-https \
  --protocol Tcp \
  --direction Inbound \
  --priority 110 \
  --source-address-prefix '*' \
  --source-port-range '*' \
  --destination-address-prefix '*' \
  --destination-port-range 443 \
  --access Allow

az network nsg rule create \
  --resource-group network-security-lab \
  --nsg-name web-nsg \
  --name allow-ssh \
  --protocol Tcp \
  --direction Inbound \
  --priority 120 \
  --source-address-prefix 'YOUR_HOME_IP/32' \
  --source-port-range '*' \
  --destination-address-prefix '*' \
  --destination-port-range 22 \
  --access Allow

# Deny all other inbound traffic
az network nsg rule create \
  --resource-group network-security-lab \
  --nsg-name web-nsg \
  --name deny-all-inbound \
  --protocol '*' \
  --direction Inbound \
  --priority 4096 \
  --source-address-prefix '*' \
  --source-port-range '*' \
  --destination-address-prefix '*' \
  --destination-port-range '*' \
  --access Deny

# Associate NSG with subnet
az network vnet subnet update \
  --resource-group network-security-lab \
  --vnet-name lab-vnet \
  --name web-subnet \
  --network-security-group web-nsg
```

#### Lab 2: Advanced NSG with Service Tags
```bash
# Create application security group
az network asg create \
  --resource-group network-security-lab \
  --name web-asg

# Create NSG with service tags
az network nsg create \
  --resource-group network-security-lab \
  --name app-nsg

# Allow Azure Load Balancer traffic
az network nsg rule create \
  --resource-group network-security-lab \
  --nsg-name app-nsg \
  --name allow-azure-lb \
  --protocol Tcp \
  --direction Inbound \
  --priority 100 \
  --source-address-prefix 'AzureLoadBalancer' \
  --source-port-range '*' \
  --destination-address-prefix '*' \
  --destination-port-range 8080 \
  --access Allow

# Allow traffic from web tier
az network nsg rule create \
  --resource-group network-security-lab \
  --nsg-name app-nsg \
  --name allow-from-web \
  --protocol Tcp \
  --direction Inbound \
  --priority 110 \
  --source-address-prefix '10.0.1.0/24' \
  --source-port-range '*' \
  --destination-address-prefix '*' \
  --destination-port-range 3000 \
  --access Allow \
  --description "Allow web servers to access application servers"
```

### NSG Best Practices

#### 1. Rule Organization
```bash
# Use descriptive naming conventions
# Priority ranges:
# 100-199: Management access (SSH, RDP)
# 200-299: Application-specific ports
# 300-399: Database access
# 400-499: Monitoring and logging
# 4096: Deny all rule
```

#### 2. Service Tags Usage
```bash
# Common service tags:
# VirtualNetwork: Traffic within VNet
# AzureLoadBalancer: Azure Load Balancer
# Internet: All internet traffic
# AzureCloud: Azure infrastructure
# Storage: Azure Storage services
```

#### 3. Application Security Groups
```bash
# Create ASGs for logical grouping
az network asg create --resource-group rg-name --name web-servers
az network asg create --resource-group rg-name --name app-servers
az network asg create --resource-group rg-name --name db-servers

# Use ASGs in NSG rules
az network nsg rule create \
  --resource-group rg-name \
  --nsg-name nsg-name \
  --name allow-web-to-app \
  --source-asgs web-servers \
  --destination-asgs app-servers \
  --access Allow
```

##  Azure Firewall

### Overview
Azure Firewall is a managed, cloud-native network security service that provides threat protection for your cloud resources.

### Key Features
- **Stateful firewall** as a service
- **Built-in high availability** with unrestricted cloud scalability
- **Availability Zones** support
- **FQDN filtering** for outbound traffic
- **Network traffic filtering** rules
- **Threat intelligence** based filtering
- **Web categories** filtering
- **Outbound SNAT** support
- **Inbound DNAT** support

### Hands-On Lab: Azure Firewall Setup

#### Lab 3: Deploy Azure Firewall
```bash
# Create firewall subnet
az network vnet subnet create \
  --resource-group network-security-lab \
  --vnet-name lab-vnet \
  --name AzureFirewallSubnet \
  --address-prefix 10.0.0.0/24

# Create public IP for firewall
az network public-ip create \
  --resource-group network-security-lab \
  --name fw-pip \
  --sku Standard \
  --allocation-method Static

# Create Azure Firewall
az network firewall create \
  --resource-group network-security-lab \
  --name lab-firewall \
  --location eastus \
  --sku AZFW_VNet \
  --zones 1 2 3

# Get firewall details
FW_ID=$(az network firewall show \
  --resource-group network-security-lab \
  --name lab-firewall \
  --query id -o tsv)

# Create firewall policy
az network firewall policy create \
  --resource-group network-security-lab \
  --name fw-policy \
  --sku Standard

# Create network rule collection
az network firewall network-rule collection create \
  --resource-group network-security-lab \
  --policy-name fw-policy \
  --name network-rule-collection-1 \
  --priority 100 \
  --action Allow \
  --rules name=allow-http protocols=TCP source-addresses='*' destination-addresses='*' destination-ports=80

# Create application rule collection
az network firewall application-rule collection create \
  --resource-group network-security-lab \
  --policy-name fw-policy \
  --name app-rule-collection-1 \
  --priority 100 \
  --action Allow \
  --fqdn-tags=WindowsUpdate
```

#### Lab 4: Firewall Rules and Policies
```bash
# Create application rule for specific FQDNs
az network firewall application-rule collection create \
  --resource-group network-security-lab \
  --policy-name fw-policy \
  --name allow-specific-sites \
  --priority 200 \
  --action Allow \
  --rules name=allow-github protocols=Http=80,Https=443 target-fqdns=github.com,www.github.com

# Create NAT rule collection
az network firewall nat-rule collection create \
  --resource-group network-security-lab \
  --policy-name fw-policy \
  --name nat-rdp \
  --priority 100 \
  --action Dnat \
  --rules name=rdp-rule protocols=TCP source-addresses='*' destination-addresses=FW_PUBLIC_IP destination-ports=3389 translated-address=VM_PRIVATE_IP translated-port=3389

# Associate policy with firewall
az network firewall update \
  --resource-group network-security-lab \
  --name lab-firewall \
  --firewall-policy fw-policy
```

### Firewall Best Practices

#### 1. Rule Management
```bash
# Use descriptive rule names
# Group related rules in collections
# Set appropriate priorities
# Regular rule review and cleanup
```

#### 2. Monitoring and Logging
```bash
# Enable diagnostic logging
az monitor diagnostic-settings create \
  --resource $FW_ID \
  --name fw-diagnostics \
  --workspace /subscriptions/SUB_ID/resourceGroups/RG_NAME/providers/Microsoft.OperationalInsights/workspaces/WORKSPACE_NAME \
  --metrics '[{"category": "AllMetrics", "enabled": true}]' \
  --logs '[{"category": "AzureFirewallApplicationRule", "enabled": true}, {"category": "AzureFirewallNetworkRule", "enabled": true}]'
```

##  DDoS Protection

### Overview
Azure DDoS Protection provides enhanced DDoS mitigation capabilities for your Azure resources.

### Hands-On Lab: DDoS Protection Setup

#### Lab 5: Enable DDoS Protection
```bash
# Create DDoS protection plan
az network ddos-protection create \
  --resource-group network-security-lab \
  --name ddos-plan \
  --location eastus \
  --vnets lab-vnet

# Enable DDoS protection on VNet
az network vnet update \
  --resource-group network-security-lab \
  --name lab-vnet \
  --ddos-protection true \
  --ddos-protection-plan ddos-plan

# Create DDoS telemetry alert
az monitor metrics alert create \
  --name "DDoS Attack Detected" \
  --resource-group network-security-lab \
  --scopes "/subscriptions/SUB_ID/resourceGroups/network-security-lab/providers/Microsoft.Network/ddosProtectionPlans/ddos-plan" \
  --condition "avg Microsoft.Network/ddosProtectionPlans/ddosAttackBandwidth > 0" \
  --window-size 5m \
  --evaluation-frequency 1m \
  --severity 2
```

##  Application Gateway and WAF

### Overview
Azure Application Gateway is a web traffic load balancer that enables you to manage traffic to your web applications. The Web Application Firewall (WAF) provides centralized protection of your web applications from common exploits and vulnerabilities.

### Hands-On Lab: Application Gateway with WAF

#### Lab 6: Deploy Application Gateway with WAF
```bash
# Create subnet for Application Gateway
az network vnet subnet create \
  --resource-group network-security-lab \
  --vnet-name lab-vnet \
  --name app-gw-subnet \
  --address-prefix 10.0.2.0/24

# Create public IP for Application Gateway
az network public-ip create \
  --resource-group network-security-lab \
  --name app-gw-pip \
  --sku Standard \
  --allocation-method Static

# Create Application Gateway with WAF
az network application-gateway create \
  --resource-group network-security-lab \
  --name app-gw-waf \
  --location eastus \
  --sku WAF_v2 \
  --capacity 2 \
  --http-settings-cookie-based-affinity Enabled \
  --public-ip-address app-gw-pip \
  --vnet-name lab-vnet \
  --subnet app-gw-subnet \
  --servers 10.0.1.4 10.0.1.5

# Configure WAF policy
az network application-gateway waf-policy create \
  --resource-group network-security-lab \
  --name waf-policy \
  --location eastus \
  --enabled true \
  --mode Prevention \
  --request-body-check true \
  --file-upload-limit 100

# Enable OWASP rules
az network application-gateway waf-policy managed-rule-set add \
  --resource-group network-security-lab \
  --policy-name waf-policy \
  --type OWASP \
  --version 3.2 \
  --rule-group-name REQUEST-942-APPLICATION-ATTACK-SQLI \
  --rules 942100 942110 942120 942130 942140 942150 942160 942170 942180 942190

# Associate WAF policy with Application Gateway
az network application-gateway update \
  --resource-group network-security-lab \
  --name app-gw-waf \
  --firewall-policy-name waf-policy
```

### WAF Custom Rules
```bash
# Create custom WAF rule
az network application-gateway waf-policy custom-rule create \
  --resource-group network-security-lab \
  --policy-name waf-policy \
  --name block-malicious-ua \
  --priority 100 \
  --rule-type MatchRule \
  --match-variables RequestHeaders.User-Agent \
  --operator Contains \
  --match-values sqlmap nmap \
  --action Block
```

##  Network Monitoring and Threat Detection

### Azure Network Watcher
```bash
# Enable Network Watcher
az network watcher configure \
  --resource-group network-security-lab \
  --locations eastus

# Network performance monitoring
az network watcher monitor-connection \
  --resource-group network-security-lab \
  --location eastus \
  --source-resource VM_ID \
  --dest-address google.com \
  --dest-port 80

# Flow log analysis
az network watcher flow-log create \
  --resource-group network-security-lab \
  --location eastus \
  --nsg web-nsg \
  --storage-account STORAGE_ACCOUNT \
  --enabled true \
  --retention 7
```

### Traffic Analytics
```bash
# Enable Traffic Analytics
az network watcher flow-log create \
  --resource-group network-security-lab \
  --location eastus \
  --nsg web-nsg \
  --storage-account STORAGE_ACCOUNT \
  --enabled true \
  --retention 7 \
  --traffic-analytics true \
  --workspace WORKSPACE_ID
```

##  Automation and Scripting

### PowerShell Scripts
```powershell
# Create comprehensive NSG rules
function New-SecureNSGRules {
    param(
        [string]$ResourceGroup,
        [string]$NSGName
    )
    
    # Allow HTTP/HTTPS
    New-AzNetworkSecurityRuleConfig `
        -Name "Allow-HTTP" `
        -Description "Allow HTTP traffic" `
        -Access Allow `
        -Protocol Tcp `
        -Direction Inbound `
        -Priority 100 `
        -SourceAddressPrefix * `
        -SourcePortRange * `
        -DestinationAddressPrefix * `
        -DestinationPortRange 80 `
        | Set-AzNetworkSecurityGroup -Name $NSGName -ResourceGroup $ResourceGroup
    
    New-AzNetworkSecurityRuleConfig `
        -Name "Allow-HTTPS" `
        -Description "Allow HTTPS traffic" `
        -Access Allow `
        -Protocol Tcp `
        -Direction Inbound `
        -Priority 110 `
        -SourceAddressPrefix * `
        -SourcePortRange * `
        -DestinationAddressPrefix * `
        -DestinationPortRange 443 `
        | Set-AzNetworkSecurityGroup -Name $NSGName -ResourceGroup $ResourceGroup
}

# Usage
New-SecureNSGRules -ResourceGroup "network-security-lab" -NSGName "web-nsg"
```

### Azure CLI Scripts
```bash
#!/bin/bash
# Comprehensive network security setup

RESOURCE_GROUP="network-security-lab"
LOCATION="eastus"
VNET_NAME="secure-vnet"

# Create secure VNet architecture
echo "Creating secure VNet architecture..."

# Hub VNet
az network vnet create \
  --resource-group $RESOURCE_GROUP \
  --name $VNET_NAME \
  --address-prefixes 10.0.0.0/16 \
  --subnet-name hub-subnet \
  --subnet-prefix 10.0.0.0/24

# Spoke VNets
az network vnet create \
  --resource-group $RESOURCE_GROUP \
  --name web-vnet \
  --address-prefixes 10.1.0.0/16 \
  --subnet-name web-subnet \
  --subnet-prefix 10.1.1.0/24

az network vnet create \
  --resource-group $RESOURCE_GROUP \
  --name app-vnet \
  --address-prefixes 10.2.0.0/16 \
  --subnet-name app-subnet \
  --subnet-prefix 10.2.1.0/24

az network vnet create \
  --resource-group $RESOURCE_GROUP \
  --name data-vnet \
  --address-prefixes 10.3.0.0/16 \
  --subnet-name data-subnet \
  --subnet-prefix 10.3.1.0/24

# Peer VNets
az network vnet peering create \
  --resource-group $RESOURCE_GROUP \
  --name hub-to-web \
  --vnet-name $VNET_NAME \
  --remote-vnet web-vnet \
  --allow-vnet-access true

az network vnet peering create \
  --resource-group $RESOURCE_GROUP \
  --name web-to-hub \
  --vnet-name web-vnet \
  --remote-vnet $VNET_NAME \
  --allow-vnet-access true

echo "Secure VNet architecture created successfully!"
```

##  Security Best Practices Checklist

### Network Design
- [ ] Implement hub-and-spoke architecture
- [ ] Use network segmentation
- [ ] Deploy Azure Firewall in hub
- [ ] Configure VNet peering appropriately
- [ ] Enable DDoS protection

### NSG Configuration
- [ ] Follow least privilege principle
- [ ] Use service tags where appropriate
- [ ] Implement application security groups
- [ ] Regular rule review and cleanup
- [ ] Enable NSG flow logging

### Application Gateway/WAF
- [ ] Enable WAF in prevention mode
- [ ] Configure OWASP CRS rules
- [ ] Implement custom rules for specific threats
- [ ] Enable logging and monitoring
- [ ] Regularly review WAF logs

### Monitoring and Alerting
- [ ] Enable Network Watcher
- [ ] Configure flow logs
- [ ] Set up Traffic Analytics
- [ ] Create meaningful alerts
- [ ] Implement automated response

##  Common Scenarios and Solutions

### Scenario 1: Securing Multi-Tier Applications
```bash
# Create separate subnets for each tier
az network vnet subnet create --name web-subnet --address-prefix 10.0.1.0/24
az network vnet subnet create --name app-subnet --address-prefix 10.0.2.0/24
az network vnet subnet create --name db-subnet --address-prefix 10.0.3.0/24

# Configure NSGs for each tier
# Web tier: Allow HTTP/HTTPS from Internet
# App tier: Allow traffic from web tier only
# DB tier: Allow traffic from app tier only
```

### Scenario 2: Implementing Zero Trust Network
```bash
# Use Azure Firewall for all traffic inspection
# Implement micro-segmentation
# Use Application Security Groups
# Enable just-in-time access
# Monitor all traffic flows
```

### Scenario 3: Hybrid Network Security
```bash
# Use VPN Gateway for secure connectivity
# Implement Azure Firewall for internet filtering
# Configure ExpressRoute with private peering
# Use BGP for route management
```

##  Additional Resources

### Documentation
- [Azure Network Security Documentation](https://docs.microsoft.com/azure/security/fundamentals/network-best-practices)
- [Azure Firewall Documentation](https://docs.microsoft.com/azure/firewall/)
- [Application Gateway Documentation](https://docs.microsoft.com/azure/application-gateway/)

### Tools and Utilities
- [Azure Network Watcher](https://docs.microsoft.com/azure/network-watcher/)
- [Azure Advisor](https://docs.microsoft.com/azure/advisor/)
- [Azure Security Center](https://docs.microsoft.com/azure/security-center/)

### Training
- [AZ-500: Azure Security Technologies](https://docs.microsoft.com/learn/certifications/azure-security-associate/)
- [Microsoft Learn: Network Security](https://docs.microsoft.com/learn/paths/secure-your-cloud-network/)

---

** Master Azure network security** by implementing these best practices and hands-on labs in your environment.
