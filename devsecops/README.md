# DevSecOps Practices

## Overview

DevSecOps integrates security practices into DevOps processes, enabling organizations to build secure software at scale. This guide covers DevSecOps principles, implementation strategies, and best practices for cloud environments.

## Learning Objectives

By mastering DevSecOps practices, you will:
- Understand DevSecOps principles and methodologies
- Implement security in CI/CD pipelines
- Automate security testing and validation
- Integrate security monitoring into operations
- Build security-first development cultures
- Implement continuous security monitoring

## DevSecOps Framework

### Core Principles
1. **Security as Code**: Implement security controls as code
2. **Continuous Security**: Integrate security throughout the lifecycle
3. **Automation**: Automate security processes and controls
4. **Collaboration**: Foster security collaboration across teams
5. **Measurement**: Measure and improve security metrics

### DevSecOps Lifecycle
```
Plan -> Code -> Build -> Test -> Release -> Deploy -> Operate -> Monitor
  |       |       |       |        |        |         |         |
  |       |       |       |        |        |         |         v
  |       |       |       |        |        |         |    Continuous Monitoring
  |       |       |       |        |        |         |
  |       |       |       |        |        |         v
  |       |       |       |        |        |    Continuous Compliance
  |       |       |       |        |        |
  |       |       |       |        |        v
  |       |       |       |        |    Continuous Deployment
  |       |       |       |        |
  |       |       |       |        v
  |       |       |       |    Continuous Testing
  |       |       |       |
  |       |       |       v
  |       |       |    Continuous Integration
  |       |       |
  |       |       v
  |       |    Continuous Development
  |       |
  |       v
  |    Continuous Planning
  |
  v
Security by Design
```

## CI/CD Security Integration

### 1. Secure Pipeline Architecture

#### GitHub Actions Security Pipeline
```yaml
# .github/workflows/security-pipeline.yml
name: Security Pipeline

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

env:
  REGISTRY: ghcr.io
  IMAGE_NAME: ${{ github.repository }}

jobs:
  security-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
      security-events: write

    steps:
    - name: Checkout code
      uses: actions/checkout@v3

    - name: Setup Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.9'

    - name: Install security tools
      run: |
        pip install bandit safety semgrep
        npm install -g audit-ci

    - name: Static Application Security Testing (SAST)
      run: |
        echo "Running SAST scans..."
        bandit -r . -f json -o bandit-report.json || true
        semgrep --config=auto --json --output=semgrep-report.json . || true
        safety check --json --output safety-report.json || true

    - name: Dependency Scanning
      run: |
        echo "Scanning dependencies..."
        audit-ci --moderate

    - name: Infrastructure as Code Security
      run: |
        echo "Scanning IaC..."
        pip install checkov
        checkov -d . --framework terraform --output json > checkov-report.json || true

    - name: Container Security
      run: |
        echo "Scanning container images..."
        docker build -t ${{ env.IMAGE_NAME }}:${{ github.sha }} .
        trivy image --format json --output trivy-report.json ${{ env.IMAGE_NAME }}:${{ github.sha }}

    - name: Upload Security Scans
      uses: actions/upload-artifact@v3
      with:
        name: security-reports
        path: |
          bandit-report.json
          semgrep-report.json
          safety-report.json
          checkov-report.json
          trivy-report.json

    - name: Security Gate
      run: |
        echo "Evaluating security gate..."
        python scripts/security-gate.py

    - name: Build and Push Container
      if: github.ref == 'refs/heads/main'
      run: |
        echo "Building and pushing secure container..."
        docker build -t ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }} .
        docker push ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }}

    - name: Generate SBOM
      run: |
        echo "Generating Software Bill of Materials..."
        pip install cyclonedx-bom
        cyclonedx-py -o json -i . > sbom.json

    - name: Upload SBOM
      uses: actions/upload-artifact@v3
      with:
        name: sbom
        path: sbom.json
```

#### Azure DevOps Security Pipeline
```yaml
# azure-pipelines.yml
trigger:
  branches:
    include:
    - main
    - develop

pr:
  branches:
    include:
    - main

variables:
  - group: security-variables
  - name: imageRepository
    value: 'secure-app'
  - name: containerRegistry
    value: 'myregistry.azurecr.io'
  - name: dockerfilePath
    value: '$(Build.SourcesDirectory)/Dockerfile'
  - name: tag
    value: '$(Build.BuildId)'

stages:
- stage: Validate
  displayName: 'Security Validation Stage'
  jobs:
  - job: SecurityValidation
    displayName: 'Security Validation'
    pool:
      vmImage: 'ubuntu-latest'
    steps:
    - task: UsePythonVersion@0
      inputs:
        versionSpec: '3.9'
        addToPath: true

    - script: |
        pip install bandit safety checkov semgrep
        echo "Running security validation..."
      displayName: 'Install Security Tools'

    - script: |
        bandit -r . -f json -o $(Build.ArtifactStagingDirectory)/bandit-report.json
        safety check --json --output $(Build.ArtifactStagingDirectory)/safety-report.json
        checkov -d . --framework terraform --output json $(Build.ArtifactStagingDirectory)/checkov-report.json
        semgrep --config=auto --json --output $(Build.ArtifactStagingDirectory)/semgrep-report.json .
      displayName: 'Run Security Scans'

    - task: PublishBuildArtifacts@1
      inputs:
        pathToPublish: '$(Build.ArtifactStagingDirectory)'
        artifactName: 'security-reports'

- stage: Build
  displayName: 'Build Stage'
  dependsOn: Validate
  jobs:
  - job: Build
    displayName: 'Build Job'
    pool:
      vmImage: 'ubuntu-latest'
    steps:
    - task: Docker@2
      displayName: 'Build and Push Container'
      inputs:
        containerRegistry: '$(containerRegistryConnection)'
        repository: '$(imageRepository)'
        command: 'buildAndPush'
        Dockerfile: '$(dockerfilePath)'
        tags: |
          $(tag)
          latest

    - script: |
        echo "Generating SBOM..."
        pip install cyclonedx-bom
        cyclonedx-py -o json -i . > $(Build.ArtifactStagingDirectory)/sbom.json
      displayName: 'Generate SBOM'

    - task: PublishBuildArtifacts@1
      inputs:
        pathToPublish: '$(Build.ArtifactStagingDirectory)'
        artifactName: 'sbom'
```

### 2. Security Gate Implementation

#### Security Gate Script
```python
# scripts/security-gate.py
import json
import sys
import os

class SecurityGate:
    def __init__(self):
        self.thresholds = {
            'bandit_high': 0,
            'bandit_medium': 5,
            'semgrep_high': 0,
            'semgrep_medium': 10,
            'safety_vulnerabilities': 0,
            'checkov_failed': 0,
            'trivy_high': 0,
            'trivy_medium': 5
        }
    
    def load_report(self, filename):
        """Load security report"""
        try:
            with open(filename, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {}
    
    def evaluate_bandit(self, report):
        """Evaluate Bandit report"""
        if not report:
            return True, "No Bandit report found"
        
        high_issues = len([r for r in report.get('results', []) if r.get('issue_severity') == 'HIGH'])
        medium_issues = len([r for r in report.get('results', []) if r.get('issue_severity') == 'MEDIUM'])
        
        if high_issues > self.thresholds['bandit_high']:
            return False, f"Too many high severity Bandit issues: {high_issues}"
        
        if medium_issues > self.thresholds['bandit_medium']:
            return False, f"Too many medium severity Bandit issues: {medium_issues}"
        
        return True, f"Bandit scan passed: {high_issues} high, {medium_issues} medium"
    
    def evaluate_semgrep(self, report):
        """Evaluate Semgrep report"""
        if not report:
            return True, "No Semgrep report found"
        
        high_issues = len([r for r in report.get('results', []) if r.get('metadata', {}).get('severity') == 'ERROR'])
        medium_issues = len([r for r in report.get('results', []) if r.get('metadata', {}).get('severity') == 'WARNING'])
        
        if high_issues > self.thresholds['semgrep_high']:
            return False, f"Too many high severity Semgrep issues: {high_issues}"
        
        if medium_issues > self.thresholds['semgrep_medium']:
            return False, f"Too many medium severity Semgrep issues: {medium_issues}"
        
        return True, f"Semgrep scan passed: {high_issues} high, {medium_issues} medium"
    
    def evaluate_safety(self, report):
        """Evaluate Safety report"""
        if not report:
            return True, "No Safety report found"
        
        vulnerabilities = len(report.get('vulnerabilities', []))
        
        if vulnerabilities > self.thresholds['safety_vulnerabilities']:
            return False, f"Too many Safety vulnerabilities: {vulnerabilities}"
        
        return True, f"Safety scan passed: {vulnerabilities} vulnerabilities"
    
    def evaluate_checkov(self, report):
        """Evaluate Checkov report"""
        if not report:
            return True, "No Checkov report found"
        
        failed_checks = sum(1 for r in report.get('results', {}).get('failed_checks', []))
        
        if failed_checks > self.thresholds['checkov_failed']:
            return False, f"Too many Checkov failed checks: {failed_checks}"
        
        return True, f"Checkov scan passed: {failed_checks} failed checks"
    
    def evaluate_trivy(self, report):
        """Evaluate Trivy report"""
        if not report:
            return True, "No Trivy report found"
        
        high_issues = len([r for r in report.get('Results', [{}])[0].get('Vulnerabilities', []) if r.get('Severity') == 'HIGH' or r.get('Severity') == 'CRITICAL'])
        medium_issues = len([r for r in report.get('Results', [{}])[0].get('Vulnerabilities', []) if r.get('Severity') == 'MEDIUM'])
        
        if high_issues > self.thresholds['trivy_high']:
            return False, f"Too many high severity Trivy issues: {high_issues}"
        
        if medium_issues > self.thresholds['trivy_medium']:
            return False, f"Too many medium severity Trivy issues: {medium_issues}"
        
        return True, f"Trivy scan passed: {high_issues} high, {medium_issues} medium"
    
    def evaluate_all(self):
        """Evaluate all security reports"""
        results = []
        
        # Load all reports
        bandit_report = self.load_report('bandit-report.json')
        semgrep_report = self.load_report('semgrep-report.json')
        safety_report = self.load_report('safety-report.json')
        checkov_report = self.load_report('checkov-report.json')
        trivy_report = self.load_report('trivy-report.json')
        
        # Evaluate each report
        passed, message = self.evaluate_bandit(bandit_report)
        results.append(('Bandit', passed, message))
        
        passed, message = self.evaluate_semgrep(semgrep_report)
        results.append(('Semgrep', passed, message))
        
        passed, message = self.evaluate_safety(safety_report)
        results.append(('Safety', passed, message))
        
        passed, message = self.evaluate_checkov(checkov_report)
        results.append(('Checkov', passed, message))
        
        passed, message = self.evaluate_trivy(trivy_report)
        results.append(('Trivy', passed, message))
        
        # Print results
        print("Security Gate Results:")
        print("=" * 50)
        
        all_passed = True
        for tool, passed, message in results:
            status = "PASS" if passed else "FAIL"
            print(f"{tool:10} {status:5} {message}")
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
    gate = SecurityGate()
    sys.exit(gate.evaluate_all())
```

## Infrastructure as Code Security

### 1. Terraform Security Modules

#### Secure VNet Module
```hcl
# modules/secure-vnet/main.tf
variable "vnet_name" {
  description = "Name of the virtual network"
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

resource "azurerm_resource_group" "main" {
  name     = var.vnet_name
  location = var.location
  tags     = var.tags
}

resource "azurerm_virtual_network" "main" {
  name                = var.vnet_name
  address_space       = var.address_space
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  ddos_protection_plan = var.enable_ddos_protection ? azurerm_network_ddos_protection_plan.main[0].id : null
  tags                = var.tags
}

resource "azurerm_network_ddos_protection_plan" "main" {
  count               = var.enable_ddos_protection ? 1 : 0
  name                = "${var.vnet_name}-ddos"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  tags                = var.tags
}

resource "azurerm_network_security_group" "main" {
  for_each            = { for subnet in var.subnets : subnet.name => subnet }
  name                = "${var.vnet_name}-${each.key}-nsg"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  tags                = var.tags
}

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
  resource_group_name       = azurerm_resource_group.main.name
  network_security_group_name = azurerm_network_security_group.main[each.value.subnet.name].name
}

resource "azurerm_subnet" "main" {
  for_each             = { for subnet in var.subnets : subnet.name => subnet }
  name                 = each.key
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = [each.value.address_prefix]
  network_security_group_id = azurerm_network_security_group.main[each.key].id
}

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

#### Secure Storage Module
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
}

variable "account_replication_type" {
  description = "Storage account replication type"
  type        = string
  default     = "LRS"
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

resource "azurerm_storage_account" "main" {
  name                     = var.storage_account_name
  resource_group_name      = var.resource_group_name
  location                 = var.location
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

resource "azurerm_storage_container" "main" {
  for_each              = { for container in var.containers : container.name => container }
  name                  = each.key
  storage_account_name  = azurerm_storage_account.main.name
  container_access_type = each.value.access_type
}

resource "azurerm_storage_management_policy" "main" {
  storage_account_id = azurerm_storage_account.main.id
  
  rule {
    name    = "lifecycle"
    enabled = true
    
    filters {
      prefix_match = ["logs/"]
      blob_types   = ["block_blob"]
    }
    
    actions {
      base_blob {
        delete_after_days_since_modification_greater_than = 365
      }
    }
  }
}

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
```

### 2. Policy as Code

#### Azure Policy Definitions
```json
{
  "properties": {
    "displayName": "Secure Storage Accounts",
    "policyType": "Custom",
    "mode": "Indexed",
    "description": "Ensures storage accounts meet security requirements",
    "metadata": {
      "version": "1.0.0",
      "category": "Storage"
    },
    "parameters": {
      "effect": {
        "type": "String",
        "metadata": {
          "displayName": "Effect",
          "description": "Deny or Audit the policy"
        },
        "allowedValues": ["Deny", "Audit"],
        "defaultValue": "Deny"
      }
    },
    "policyRule": {
      "if": {
        "allOf": [
          {
            "field": "type",
            "equals": "Microsoft.Storage/storageAccounts"
          },
          {
            "anyOf": [
              {
                "field": "Microsoft.Storage/storageAccounts/allowBlobPublicAccess",
                "equals": true
              },
              {
                "field": "Microsoft.Storage/storageAccounts/minimumTlsVersion",
                "notEquals": "TLS1_2"
              },
              {
                "field": "Microsoft.Storage/storageAccounts/networkAcls.defaultAction",
                "equals": "Allow"
              }
            ]
          }
        ]
      },
      "then": {
        "effect": "[parameters('effect')]"
      }
    }
  }
}
```

#### Terraform Policy Implementation
```hcl
# policies/secure-compute.tf
resource "azurerm_policy_definition" "secure_compute" {
  name         = "secure-compute-policy"
  display_name = "Secure Compute Policy"
  policy_type  = "Custom"
  mode         = "Indexed"
  
  policy_rule = jsonencode({
    if = {
      allOf = [
        {
          field = "type"
          equals = "Microsoft.Compute/virtualMachines"
        },
        {
          anyOf = [
            {
              field = "Microsoft.Compute/virtualMachines/osProfile.adminUsername"
              exists = false
            },
            {
              field = "Microsoft.Compute/virtualMachines/osProfile.adminPassword"
              exists = false
            }
          ]
        }
      ]
    }
    then = {
      effect = "Deny"
    }
  })
  
  metadata = jsonencode({
    version  = "1.0.0"
    category = "Compute"
  })
}

resource "azurerm_policy_assignment" "secure_compute" {
  name                 = "secure-compute-assignment"
  scope                = azurerm_resource_group.main.id
  policy_definition_id = azurerm_policy_definition.secure_compute.id
  description          = "Enforces secure compute configuration"
  display_name        = "Secure Compute Assignment"
}
```

## Security Monitoring and Observability

### 1. Application Security Monitoring

#### OpenTelemetry Security Integration
```python
# security_monitoring.py
from opentelemetry import trace, metrics
from opentelemetry.exporter.jaeger.thrift import JaegerExporter
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.exporter.prometheus import PrometheusMetricReader
import time
import json

class SecurityMonitoring:
    def __init__(self):
        # Setup tracing
        trace.set_tracer_provider(TracerProvider())
        tracer = trace.get_tracer(__name__)
        
        jaeger_exporter = JaegerExporter(
            agent_host_name="localhost",
            agent_port=6831,
        )
        
        span_processor = BatchSpanProcessor(jaeger_exporter)
        trace.get_tracer_provider().add_span_processor(span_processor)
        
        # Setup metrics
        reader = PrometheusMetricReader()
        provider = MeterProvider(metric_readers=[reader])
        metrics.set_meter_provider(provider)
        
        self.meter = metrics.get_meter(__name__)
        self.security_events_counter = self.meter.create_counter(
            "security_events_total",
            description="Total number of security events"
        )
        self.security_failures_counter = self.meter.create_counter(
            "security_failures_total",
            description="Total number of security failures"
        )
        self.response_time_histogram = self.meter.create_histogram(
            "security_check_duration_seconds",
            description="Time taken for security checks"
        )
        
        self.tracer = tracer
    
    def track_security_event(self, event_type, severity, details):
        """Track security event"""
        with self.tracer.start_as_current_span("security_event") as span:
            span.set_attribute("event.type", event_type)
            span.set_attribute("event.severity", severity)
            span.set_attribute("event.details", json.dumps(details))
            
            # Record metrics
            self.security_events_counter.add(
                1,
                {"event_type": event_type, "severity": severity}
            )
    
    def track_security_failure(self, failure_type, component, details):
        """Track security failure"""
        with self.tracer.start_as_current_span("security_failure") as span:
            span.set_attribute("failure.type", failure_type)
            span.set_attribute("failure.component", component)
            span.set_attribute("failure.details", json.dumps(details))
            
            # Record metrics
            self.security_failures_counter.add(
                1,
                {"failure_type": failure_type, "component": component}
            )
    
    def measure_security_check(self, check_name, check_function):
        """Measure security check performance"""
        start_time = time.time()
        
        try:
            result = check_function()
            success = True
        except Exception as e:
            result = None
            success = False
            self.track_security_failure("check_failure", check_name, str(e))
        
        duration = time.time() - start_time
        
        # Record metrics
        self.response_time_histogram.record(
            duration,
            {"check_name": check_name, "success": str(success)}
        )
        
        return result

# Usage
monitor = SecurityMonitoring()

def authentication_check():
    """Sample authentication check"""
    # Implement authentication logic
    return True

def authorization_check():
    """Sample authorization check"""
    # Implement authorization logic
    return True

# Track security events
monitor.track_security_event("authentication_attempt", "info", {"user": "user123"})
monitor.track_security_event("authorization_check", "info", {"resource": "data456"})

# Measure security checks
auth_result = monitor.measure_security_check("authentication", authentication_check)
authz_result = monitor.measure_security_check("authorization", authorization_check)
```

### 2. Log Analysis and Alerting

#### Security Log Analysis
```python
# log_analysis.py
import re
import json
from datetime import datetime, timedelta
from collections import defaultdict

class SecurityLogAnalyzer:
    def __init__(self):
        self.patterns = {
            'failed_login': re.compile(r'failed.*login|authentication.*failed', re.IGNORECASE),
            'sql_injection': re.compile(r'select.*from|union.*select|drop.*table', re.IGNORECASE),
            'xss': re.compile(r'<script|javascript:|onerror=', re.IGNORECASE),
            'privilege_escalation': re.compile(r'sudo|su|escalat', re.IGNORECASE),
            'data_exfiltration': re.compile(r'download.*large|transfer.*bulk', re.IGNORECASE)
        }
        
        self.alert_thresholds = {
            'failed_login': 5,
            'sql_injection': 1,
            'xss': 1,
            'privilege_escalation': 1,
            'data_exfiltration': 1
        }
    
    def analyze_log_entry(self, log_entry):
        """Analyze single log entry"""
        timestamp = log_entry.get('timestamp', datetime.utcnow())
        message = log_entry.get('message', '')
        source = log_entry.get('source', 'unknown')
        
        detected_threats = []
        
        for threat_type, pattern in self.patterns.items():
            if pattern.search(message):
                detected_threats.append({
                    'type': threat_type,
                    'timestamp': timestamp,
                    'source': source,
                    'message': message,
                    'severity': self.get_severity(threat_type)
                })
        
        return detected_threats
    
    def get_severity(self, threat_type):
        """Get severity level for threat type"""
        severity_map = {
            'failed_login': 'medium',
            'sql_injection': 'high',
            'xss': 'high',
            'privilege_escalation': 'critical',
            'data_exfiltration': 'critical'
        }
        return severity_map.get(threat_type, 'medium')
    
    def analyze_log_batch(self, log_entries):
        """Analyze batch of log entries"""
        threats = []
        threat_counts = defaultdict(int)
        
        for entry in log_entries:
            entry_threats = self.analyze_log_entry(entry)
            threats.extend(entry_threats)
            
            for threat in entry_threats:
                threat_counts[threat['type']] += 1
        
        # Generate alerts
        alerts = []
        for threat_type, count in threat_counts.items():
            if count >= self.alert_thresholds[threat_type]:
                alerts.append({
                    'type': threat_type,
                    'count': count,
                    'severity': self.get_severity(threat_type),
                    'timestamp': datetime.utcnow(),
                    'message': f"Threshold exceeded for {threat_type}: {count} occurrences"
                })
        
        return threats, alerts
    
    def generate_security_report(self, threats, alerts):
        """Generate security analysis report"""
        report = {
            'analysis_time': datetime.utcnow().isoformat(),
            'summary': {
                'total_threats': len(threats),
                'total_alerts': len(alerts),
                'threat_types': list(set(t['type'] for t in threats)),
                'severity_distribution': self.calculate_severity_distribution(threats)
            },
            'threats': threats,
            'alerts': alerts,
            'recommendations': self.generate_recommendations(threats, alerts)
        }
        
        return report
    
    def calculate_severity_distribution(self, threats):
        """Calculate severity distribution"""
        distribution = defaultdict(int)
        for threat in threats:
            distribution[threat['severity']] += 1
        return dict(distribution)
    
    def generate_recommendations(self, threats, alerts):
        """Generate security recommendations"""
        recommendations = []
        
        threat_types = set(t['type'] for t in threats)
        
        if 'failed_login' in threat_types:
            recommendations.append({
                'priority': 'high',
                'category': 'authentication',
                'recommendation': 'Implement account lockout policies and multi-factor authentication'
            })
        
        if 'sql_injection' in threat_types:
            recommendations.append({
                'priority': 'critical',
                'category': 'application_security',
                'recommendation': 'Implement input validation and parameterized queries'
            })
        
        if 'xss' in threat_types:
            recommendations.append({
                'priority': 'high',
                'category': 'application_security',
                'recommendation': 'Implement output encoding and Content Security Policy'
            })
        
        if 'privilege_escalation' in threat_types:
            recommendations.append({
                'priority': 'critical',
                'category': 'access_control',
                'recommendation': 'Review and restrict privileged access'
            })
        
        if 'data_exfiltration' in threat_types:
            recommendations.append({
                'priority': 'critical',
                'category': 'data_protection',
                'recommendation': 'Implement data loss prevention controls'
            })
        
        return recommendations

# Usage
analyzer = SecurityLogAnalyzer()

# Sample log entries
log_entries = [
    {
        'timestamp': datetime.utcnow(),
        'message': 'Failed login attempt for user admin',
        'source': 'auth-service'
    },
    {
        'timestamp': datetime.utcnow(),
        'message': 'SQL injection attempt detected: SELECT * FROM users',
        'source': 'web-app'
    },
    {
        'timestamp': datetime.utcnow(),
        'message': 'XSS attempt: <script>alert("xss")</script>',
        'source': 'web-app'
    }
]

threats, alerts = analyzer.analyze_log_batch(log_entries)
report = analyzer.generate_security_report(threats, alerts)

print(json.dumps(report, indent=2))
```

## Best Practices

### 1. Security Integration
- **Shift Left**: Integrate security early in development
- **Automate Everything**: Automate security processes
- **Fail Fast**: Fail fast and fix quickly
- **Continuous Improvement**: Continuously improve security

### 2. Tool Integration
- **Unified Platform**: Use unified security platform
- **API Integration**: Integrate tools via APIs
- **Data Sharing**: Share security data across tools
- **Consistent Configuration**: Maintain consistent configurations

### 3. Team Collaboration
- **Cross-Functional Teams**: Build cross-functional teams
- **Shared Responsibility**: Share security responsibility
- **Regular Communication**: Regular security communication
- **Training and Awareness**: Regular security training

---

**Implement comprehensive DevSecOps practices** by integrating security throughout your development and operations processes.
