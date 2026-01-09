#  Lab: Secure Web Application Deployment

##  Overview

In this hands-on lab, you'll deploy a secure three-tier web application on Azure, implementing defense-in-depth security controls. You'll learn to configure network security, implement SSL/TLS, set up Web Application Firewall, and monitor for security threats.

##  Learning Objectives

By completing this lab, you will:
- Deploy a secure three-tier web application architecture
- Configure Network Security Groups for traffic control
- Implement SSL/TLS encryption with Azure Application Gateway
- Set up Web Application Firewall (WAF) for protection
- Configure monitoring and alerting for security events
- Practice security incident response procedures

##  Time Estimate

- **Total Duration**: 2-3 hours
- **Setup**: 30 minutes
- **Deployment**: 60 minutes
- **Security Configuration**: 45 minutes
- **Testing & Validation**: 30 minutes

##  Architecture Overview

```
                    Internet
                        │
                ┌─────────────┐
                │ Application │
                │  Gateway +  │
                │     WAF      │
                └─────────────┘
                        │
                ┌─────────────────┐
                │   Web Tier      │
                │ (Load Balanced) │
                └─────────────────┘
                        │
                ┌─────────────────┐
                │  Application    │
                │     Tier        │
                └─────────────────┘
                        │
                ┌─────────────────┐
                │   Database      │
                │     Tier        │
                └─────────────────┘
```

##  Prerequisites

Before starting this lab, ensure you have:
- Azure subscription with appropriate permissions
- Azure CLI installed and configured
- Basic understanding of Azure services
- SSH key pair for VM access

##  Step 1: Environment Setup

### 1.1 Create Resource Group
```bash
# Set variables
RESOURCE_GROUP="secure-webapp-lab"
LOCATION="eastus"
PREFIX="secweb$(date +%s)"

# Create resource group
az group create \
  --name $RESOURCE_GROUP \
  --location $LOCATION

echo "Resource group created: $RESOURCE_GROUP"
```

### 1.2 Create Virtual Network Architecture
```bash
# Create main VNet
az network vnet create \
  --resource-group $RESOURCE_GROUP \
  --name main-vnet \
  --address-prefixes 10.0.0.0/16 \
  --subnet-name gateway-subnet \
  --subnet-prefix 10.0.0.0/24

# Create web tier subnet
az network vnet subnet create \
  --resource-group $RESOURCE_GROUP \
  --vnet-name main-vnet \
  --name web-subnet \
  --address-prefix 10.0.1.0/24

# Create application tier subnet
az network vnet subnet create \
  --resource-group $RESOURCE_GROUP \
  --vnet-name main-vnet \
  --name app-subnet \
  --address-prefix 10.0.2.0/24

# Create database tier subnet
az network vnet subnet create \
  --resource-group $RESOURCE_GROUP \
  --vnet-name main-vnet \
  --name db-subnet \
  --address-prefix 10.0.3.0/24

echo "Virtual network architecture created"
```

### 1.3 Create Network Security Groups
```bash
# Create NSG for web tier
az network nsg create \
  --resource-group $RESOURCE_GROUP \
  --name web-nsg

# Add web NSG rules
az network nsg rule create \
  --resource-group $RESOURCE_GROUP \
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
  --resource-group $RESOURCE_GROUP \
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
  --resource-group $RESOURCE_GROUP \
  --nsg-name web-nsg \
  --name allow-gateway \
  --protocol Tcp \
  --direction Inbound \
  --priority 120 \
  --source-address-prefix '10.0.0.0/24' \
  --source-port-range '*' \
  --destination-address-prefix '*' \
  --destination-port-range 8080 \
  --access Allow

# Create NSG for application tier
az network nsg create \
  --resource-group $RESOURCE_GROUP \
  --name app-nsg

az network nsg rule create \
  --resource-group $RESOURCE_GROUP \
  --nsg-name app-nsg \
  --name allow-from-web \
  --protocol Tcp \
  --direction Inbound \
  --priority 100 \
  --source-address-prefix '10.0.1.0/24' \
  --source-port-range '*' \
  --destination-address-prefix '*' \
  --destination-port-range 3000 \
  --access Allow

# Create NSG for database tier
az network nsg create \
  --resource-group $RESOURCE_GROUP \
  --name db-nsg

az network nsg rule create \
  --resource-group $RESOURCE_GROUP \
  --nsg-name db-nsg \
  --name allow-from-app \
  --protocol Tcp \
  --direction Inbound \
  --priority 100 \
  --source-address-prefix '10.0.2.0/24' \
  --source-port-range '*' \
  --destination-address-prefix '*' \
  --destination-port-range 5432 \
  --access Allow

# Associate NSGs with subnets
az network vnet subnet update \
  --resource-group $RESOURCE_GROUP \
  --vnet-name main-vnet \
  --name web-subnet \
  --network-security-group web-nsg

az network vnet subnet update \
  --resource-group $RESOURCE_GROUP \
  --vnet-name main-vnet \
  --name app-subnet \
  --network-security-group app-nsg

az network vnet subnet update \
  --resource-group $RESOURCE_GROUP \
  --vnet-name main-vnet \
  --name db-subnet \
  --network-security-group db-nsg

echo "Network Security Groups created and associated"
```

##  Step 2: Deploy Application Infrastructure

### 2.1 Create Database Server
```bash
# Create PostgreSQL server
az postgres server create \
  --resource-group $RESOURCE_GROUP \
  --name ${PREFIX}-db \
  --location $LOCATION \
  --admin-user dbadmin \
  --admin-password "SecureDB@1234!" \
  --sku-name B_Gen5_1 \
  --version 11 \
  --storage-size 5120

# Configure firewall to allow app tier access
az postgres server firewall-rule create \
  --resource-group $RESOURCE_GROUP \
  --server-name ${PREFIX}-db \
  --name allow-app-tier \
  --start-ip-address 10.0.2.0 \
  --end-ip-address 10.0.2.255

# Create database
az postgres db create \
  --resource-group $RESOURCE_GROUP \
  --server-name ${PREFIX}-db \
  --name secureapp

echo "Database server created: ${PREFIX}-db"
```

### 2.2 Create Application Tier VMs
```bash
# Create availability set for app tier
az vm availability-set create \
  --resource-group $RESOURCE_GROUP \
  --name app-availability-set \
  --location $LOCATION

# Create app tier VMs
for i in {1..2}; do
  az vm create \
    --resource-group $RESOURCE_GROUP \
    --name ${PREFIX}-app-${i} \
    --availability-set app-availability-set \
    --image UbuntuLTS \
    --size Standard_B1s \
    --vnet-name main-vnet \
    --subnet app-subnet \
    --nsg "" \
    --admin-username appuser \
    --generate-ssh-keys \
    --custom-data cloud-init-app.txt
done

echo "Application tier VMs created"
```

### 2.3 Create Web Tier VMs
```bash
# Create availability set for web tier
az vm availability-set create \
  --resource-group $RESOURCE_GROUP \
  --name web-availability-set \
  --location $LOCATION

# Create web tier VMs
for i in {1..2}; do
  az vm create \
    --resource-group $RESOURCE_GROUP \
    --name ${PREFIX}-web-${i} \
    --availability-set web-availability-set \
    --image UbuntuLTS \
    --size Standard_B1s \
    --vnet-name main-vnet \
    --subnet web-subnet \
    --nsg "" \
    --admin-username webuser \
    --generate-ssh-keys \
    --custom-data cloud-init-web.txt
done

echo "Web tier VMs created"
```

### 2.4 Create Cloud Init Files

#### Web Server Configuration
```bash
cat > cloud-init-web.txt << EOF
#cloud-config
package_upgrade: true
packages:
  - nginx
  - nodejs
  - npm

write_files:
  - path: /var/www/html/index.html
    permissions: '0644'
    content: |
      <!DOCTYPE html>
      <html>
      <head>
          <title>Secure Web Application</title>
          <style>
              body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
              .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
              .header { background: #0078d4; color: white; padding: 20px; margin: -30px -30px 30px -30px; border-radius: 8px 8px 0 0; }
              .status { background: #e8f5e8; border: 1px solid #4caf50; padding: 15px; border-radius: 4px; margin: 20px 0; }
              .security { background: #fff3cd; border: 1px solid #ffc107; padding: 15px; border-radius: 4px; margin: 20px 0; }
          </style>
      </head>
      <body>
          <div class="container">
              <div class="header">
                  <h1> Secure Web Application</h1>
                  <p>Three-tier architecture with security controls</p>
              </div>
              <h2>Application Status</h2>
              <div class="status">
                  <strong> Web Server:</strong> Running on Nginx<br>
                  <strong> SSL/TLS:</strong> Enabled via Application Gateway<br>
                  <strong> WAF:</strong> Active and protecting against attacks
              </div>
              <h2>Security Features</h2>
              <div class="security">
                  <ul>
                      <li>Network Security Groups (NSGs) for traffic control</li>
                      <li>Web Application Firewall (WAF) for OWASP protection</li>
                      <li>SSL/TLS encryption for all communications</li>
                      <li>Database access restricted to application tier</li>
                      <li>Security monitoring and alerting</li>
                  </ul>
              </div>
              <h2>API Endpoints</h2>
              <p><a href="/api/health">Health Check</a></p>
              <p><a href="/api/users">User Data (Protected)</a></p>
          </div>
      </body>
      </html>

  - path: /home/webuser/app.js
    permissions: '0644'
    content: |
      const express = require('express');
      const { Pool } = require('pg');
      const app = express();
      const port = 8080;

      // Database connection
      const pool = new Pool({
        user: 'dbadmin',
        host: '${PREFIX}-db.postgres.database.azure.com',
        database: 'secureapp',
        password: 'SecureDB@1234!',
        port: 5432,
        ssl: true
      });

      app.use(express.json());

      // Health check endpoint
      app.get('/api/health', (req, res) => {
        res.json({ 
          status: 'healthy', 
          timestamp: new Date().toISOString(),
          server: process.env.HOSTNAME || 'unknown'
        });
      });

      // Protected user endpoint
      app.get('/api/users', async (req, res) => {
        try {
          const result = await pool.query('SELECT id, username, email FROM users LIMIT 10');
          res.json(result.rows);
        } catch (err) {
          console.error(err);
          res.status(500).json({ error: 'Database error' });
        }
      });

      app.listen(port, '0.0.0.0', () => {
        console.log(\`Web server running on port \${port}\`);
      });

runcmd:
  - systemctl start nginx
  - systemctl enable nginx
  - cd /home/webuser
  - npm init -y
  - npm install express pg
  - nohup node app.js &
EOF
```

#### Application Server Configuration
```bash
cat > cloud-init-app.txt << EOF
#cloud-config
package_upgrade: true
packages:
  - nodejs
  - npm

write_files:
  - path: /home/appuser/app.js
    permissions: '0644'
    content: |
      const express = require('express');
      const { Pool } = require('pg');
      const app = express();
      const port = 3000;

      // Database connection
      const pool = new Pool({
        user: 'dbadmin',
        host: '${PREFIX}-db.postgres.database.azure.com',
        database: 'secureapp',
        password: 'SecureDB@1234!',
        port: 5432,
        ssl: true
      });

      app.use(express.json());

      // Health check
      app.get('/health', (req, res) => {
        res.json({ 
          status: 'healthy', 
          service: 'application-tier',
          timestamp: new Date().toISOString()
        });
      });

      // User management API
      app.get('/api/users', async (req, res) => {
        try {
          const result = await pool.query('SELECT id, username, email, created_at FROM users ORDER BY created_at DESC LIMIT 20');
          res.json(result.rows);
        } catch (err) {
          console.error(err);
          res.status(500).json({ error: 'Database error' });
        }
      });

      // Create user endpoint
      app.post('/api/users', async (req, res) => {
        try {
          const { username, email } = req.body;
          const result = await pool.query(
            'INSERT INTO users (username, email) VALUES ($1, $2) RETURNING id, username, email, created_at',
            [username, email]
          );
          res.status(201).json(result.rows[0]);
        } catch (err) {
          console.error(err);
          res.status(500).json({ error: 'Failed to create user' });
        }
      });

      app.listen(port, '0.0.0.0', () => {
        console.log(\`Application server running on port \${port}\`);
      });

runcmd:
  - cd /home/appuser
  - npm init -y
  - npm install express pg
  - nohup node app.js &
EOF
```

##  Step 3: Deploy Application Gateway with WAF

### 3.1 Create Public IP
```bash
az network public-ip create \
  --resource-group $RESOURCE_GROUP \
  --name app-gw-pip \
  --sku Standard \
  --allocation-method Static \
  --zone 1 2 3
```

### 3.2 Create Application Gateway
```bash
az network application-gateway create \
  --resource-group $RESOURCE_GROUP \
  --name secure-app-gw \
  --location $LOCATION \
  --sku WAF_v2 \
  --capacity 2 \
  --http-settings-cookie-based-affinity Enabled \
  --public-ip-address app-gw-pip \
  --vnet-name main-vnet \
  --subnet gateway-subnet \
  --servers ${PREFIX}-web-1 ${PREFIX}-web-2
```

### 3.3 Configure WAF Policy
```bash
# Create WAF policy
az network application-gateway waf-policy create \
  --resource-group $RESOURCE_GROUP \
  --name secure-waf-policy \
  --location $LOCATION \
  --enabled true \
  --mode Prevention \
  --request-body-check true \
  --file-upload-limit 100

# Enable OWASP CRS rules
az network application-gateway waf-policy managed-rule-set add \
  --resource-group $RESOURCE_GROUP \
  --policy-name secure-waf-policy \
  --type OWASP \
  --version 3.2 \
  --rule-group-name REQUEST-942-APPLICATION-ATTACK-SQLI \
  --rules 942100 942110 942120 942130 942140 942150 942160 942170 942180 942190

# Add custom rules
az network application-gateway waf-policy custom-rule create \
  --resource-group $RESOURCE_GROUP \
  --policy-name secure-waf-policy \
  --name block-sql-injection \
  --priority 100 \
  --rule-type MatchRule \
  --match-variables RequestBody QueryString \
  --operator Contains \
  --match-values "SELECT" "INSERT" "UPDATE" "DELETE" "DROP" "UNION" "EXEC" \
  --action Block

az network application-gateway waf-policy custom-rule create \
  --resource-group $RESOURCE_GROUP \
  --policy-name secure-waf-policy \
  --name block-xss \
  --priority 110 \
  --rule-type MatchRule \
  --match-variables RequestBody QueryString \
  --operator Contains \
  --match-values "<script>" "javascript:" "onerror=" "onload=" \
  --action Block

# Associate WAF policy with Application Gateway
az network application-gateway update \
  --resource-group $RESOURCE_GROUP \
  --name secure-app-gw \
  --firewall-policy-name secure-waf-policy
```

### 3.4 Configure Backend Pool and Settings
```bash
# Get Application Gateway details
AGW_ID=$(az network application-gateway show \
  --resource-group $RESOURCE_GROUP \
  --name secure-app-gw \
  --query id -o tsv)

# Update backend pool with web VMs
az network application-gateway address-pool update \
  --resource-group $RESOURCE_GROUP \
  --gateway-name secure-app-gw \
  --name appGatewayBackendPool \
  --servers ${PREFIX}-web-1 ${PREFIX}-web-2

# Configure HTTP settings
az network application-gateway http-settings update \
  --resource-group $RESOURCE_GROUP \
  --gateway-name secure-app-gw \
  --name appGatewayBackendSettings \
  --port 8080 \
  --protocol Http \
  --cookie-based-affinity Enabled \
  --request-timeout 30

# Configure frontend port for HTTP
az network application-gateway frontend-port create \
  --resource-group $RESOURCE_GROUP \
  --gateway-name secure-app-gw \
  --name port-80 \
  --port 80

# Configure frontend port for HTTPS
az network application-gateway frontend-port create \
  --resource-group $RESOURCE_GROUP \
  --gateway-name secure-app-gw \
  --name port-443 \
  --port 443

echo "Application Gateway with WAF configured"
```

##  Step 4: Database Setup

### 4.1 Initialize Database Schema
```bash
# Connect to database and create tables
az postgres db create \
  --resource-group $RESOURCE_GROUP \
  --server-name ${PREFIX}-db \
  --name secureapp

# Create table script
cat > init-db.sql << EOF
-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create audit table
CREATE TABLE IF NOT EXISTS audit_log (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    action VARCHAR(100) NOT NULL,
    resource VARCHAR(100) NOT NULL,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert sample data
INSERT INTO users (username, email, password_hash) VALUES 
('admin', 'admin@secureapp.com', '\$2b\$12\$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj6ukx.LFvO.'),
('user1', 'user1@secureapp.com', '\$2b\$12\$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj6ukx.LFvO.'),
('user2', 'user2@secureapp.com', '\$2b\$12\$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj6ukx.LFvO.');

-- Create index for performance
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at);
EOF

# Execute SQL script
az postgres execute \
  --resource-group $RESOURCE_GROUP \
  --server-name ${PREFIX}-db \
  --name secureapp \
  --file-path init-db.sql

echo "Database schema created and populated"
```

##  Step 5: Monitoring and Alerting

### 5.1 Enable Diagnostic Logging
```bash
# Create Log Analytics workspace
az monitor log-analytics workspace create \
  --resource-group $RESOURCE_GROUP \
  --name secure-app-law \
  --location $LOCATION

# Get workspace ID
WORKSPACE_ID=$(az monitor log-analytics workspace show \
  --resource-group $RESOURCE_GROUP \
  --name secure-app-law \
  --query customerId -o tsv)

# Get workspace resource ID
WORKSPACE_RESOURCE_ID=$(az monitor log-analytics workspace show \
  --resource-group $RESOURCE_GROUP \
  --name secure-app-law \
  --query id -o tsv)

# Enable Application Gateway diagnostics
az monitor diagnostic-settings create \
  --resource $AGW_ID \
  --name app-gw-diagnostics \
  --workspace $WORKSPACE_RESOURCE_ID \
  --logs '[{"category": "ApplicationGatewayAccessLog", "enabled": true}, {"category": "ApplicationGatewayPerformanceLog", "enabled": true}, {"category": "ApplicationGatewayFirewallLog", "enabled": true}]' \
  --metrics '[{"category": "AllMetrics", "enabled": true}]'

# Enable VM diagnostics
for vm in ${PREFIX}-web-1 ${PREFIX}-web-2 ${PREFIX}-app-1 ${PREFIX}-app-2; do
  VM_ID=$(az vm show --resource-group $RESOURCE_GROUP --name $vm --query id -o tsv)
  az monitor diagnostic-settings create \
    --resource $VM_ID \
    --name ${vm}-diagnostics \
    --workspace $WORKSPACE_RESOURCE_ID \
    --metrics '[{"category": "AllMetrics", "enabled": true}]'
done

echo "Diagnostic logging enabled"
```

### 5.2 Create Security Alerts
```bash
# WAF blocked requests alert
az monitor metrics alert create \
  --name "WAF - High Number of Blocked Requests" \
  --resource-group $RESOURCE_GROUP \
  --scopes $AGW_ID \
  --condition "avg ApplicationGatewayTotalRequests > 100" \
  --window-size 5m \
  --evaluation-frequency 1m \
  --severity 2 \
  --description "Alert when WAF blocks high number of requests"

# Database connection alert
DB_ID=$(az postgres server show --resource-group $RESOURCE_GROUP --name ${PREFIX}-db --query id -o tsv)
az monitor metrics alert create \
  --name "Database - High Connection Count" \
  --resource-group $RESOURCE_GROUP \
  --scopes $DB_ID \
  --condition "avg active_connections > 50" \
  --window-size 5m \
  --evaluation-frequency 1m \
  --severity 3

# VM CPU usage alert
for vm in ${PREFIX}-web-1 ${PREFIX}-web-2 ${PREFIX}-app-1 ${PREFIX}-app-2; do
  VM_ID=$(az vm show --resource-group $RESOURCE_GROUP --name $vm --query id -o tsv)
  az monitor metrics alert create \
    --name "${vm} - High CPU Usage" \
    --resource-group $RESOURCE_GROUP \
    --scopes $VM_ID \
    --condition "avg PercentageCPU > 80" \
    --window-size 5m \
    --evaluation-frequency 1m \
    --severity 3
done

echo "Security alerts configured"
```

##  Step 6: Security Testing

### 6.1 Get Application Gateway Public IP
```bash
APP_GW_IP=$(az network public-ip show \
  --resource-group $RESOURCE_GROUP \
  --name app-gw-pip \
  --query ipAddress -o tsv)

echo "Application Gateway Public IP: $APP_GW_IP"
echo "Access your application at: http://$APP_GW_IP"
```

### 6.2 Test Basic Functionality
```bash
# Test web application
curl -I http://$APP_GW_IP

# Test API health endpoint
curl http://$APP_GW_IP/api/health

# Test user API endpoint
curl http://$APP_GW_IP/api/users
```

### 6.3 Security Testing
```bash
# Test SQL Injection Protection
echo "Testing SQL Injection protection..."
curl -X POST http://$APP_GW_IP/api/users \
  -H "Content-Type: application/json" \
  -d '{"username": "test", "email": "test@test.com"}' \
  -w "%{http_code}\n"

# Test XSS Protection
echo "Testing XSS protection..."
curl -X GET "http://$APP_GW_IP/api/search?q=<script>alert('xss')</script>" \
  -w "%{http_code}\n"

# Test rate limiting
echo "Testing rate limiting..."
for i in {1..10}; do
  curl -s -o /dev/null -w "%{http_code} " http://$APP_GW_IP/
done
echo ""
```

### 6.4 Port Scanning
```bash
# Check open ports
nmap -sS -sV -O $APP_GW_IP

# Expected results:
# Port 80: HTTP (should be open)
# Port 443: HTTPS (should be open)
# Other ports: Should be closed or filtered
```

##  Step 7: Monitoring and Analysis

### 7.1 View Logs in Log Analytics
```bash
# Query WAF logs
az monitor log-analytics query \
  --workspace $WORKSPACE_ID \
  --analytics-query "AzureDiagnostics | where Category == 'ApplicationGatewayFirewallLog' | take 10"

# Query access logs
az monitor log-analytics query \
  --workspace $WORKSPACE_ID \
  --analytics-query "AzureDiagnostics | where Category == 'ApplicationGatewayAccessLog' | take 10"

# Query performance metrics
az monitor log-analytics query \
  --workspace $WORKSPACE_ID \
  --analytics-query "AzureMetrics | where Name contains 'ApplicationGatewayTotalRequests' | summarize avg(Val) by bin(TimeGenerated, 5m)"
```

### 7.2 Create Security Dashboard
```bash
# Create dashboard JSON
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
                    "resourceId": "$AGW_ID",
                    "metrics": [
                      {
                        "name": "ApplicationGatewayTotalRequests",
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
  --resource-group $RESOURCE_GROUP \
  --name "Security Dashboard" \
  --input-path security-dashboard.json
```

##  Lab Completion Checklist

### Infrastructure Deployment
- [ ] Resource group created
- [ ] Virtual network architecture deployed
- [ ] Network Security Groups configured
- [ ] Database server deployed and secured
- [ ] Web and application tier VMs created
- [ ] Application Gateway with WAF deployed

### Security Configuration
- [ ] NSG rules implemented correctly
- [ ] WAF policy configured with OWASP rules
- [ ] Custom WAF rules for SQLi and XSS
- [ ] Database access restricted to application tier
- [ ] SSL/TLS termination at Application Gateway

### Monitoring and Alerting
- [ ] Log Analytics workspace created
- [ ] Diagnostic logging enabled
- [ ] Security alerts configured
- [ ] Security dashboard created

### Testing and Validation
- [ ] Basic functionality tested
- [ ] Security controls tested
- [ ] WAF rules validated
- [ ] Monitoring working correctly

##  Key Takeaways

1. **Defense in Depth**: Multiple layers of security provide comprehensive protection
2. **Network Segmentation**: Proper network design limits lateral movement
3. **Web Application Firewall**: Essential for protecting against web attacks
4. **Monitoring and Alerting**: Critical for detecting and responding to threats
5. **Least Privilege**: Restrict access to only what's necessary

##  Next Steps

1. **Advanced WAF Configuration**: Explore custom rules and bot protection
2. **SSL/TLS Optimization**: Implement end-to-end encryption
3. **Automated Security Testing**: Integrate security testing into CI/CD
4. **Compliance Monitoring**: Set up compliance reporting
5. **Incident Response**: Develop and test incident response procedures

##  Cleanup

**IMPORTANT**: Clean up resources to avoid charges
```bash
# Delete resource group and all resources
az group delete --name $RESOURCE_GROUP --yes --no-wait

echo "Cleanup initiated. Resources will be deleted shortly."
```

---

** Congratulations!** You've successfully deployed a secure three-tier web application with comprehensive security controls, monitoring, and alerting. You've gained hands-on experience with Azure network security, WAF configuration, and security monitoring.
