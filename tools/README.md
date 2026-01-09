# Security Tools and Scripts

## Overview

This section provides a comprehensive collection of security tools, scripts, and utilities for cloud security assessments, monitoring, and automation. These tools are designed for educational purposes and can be used in lab environments.

## Learning Objectives

By using these tools and scripts, you will:
- Master security assessment techniques
- Automate security monitoring and alerting
- Develop custom security tools
- Understand security tool integration
- Build security automation workflows
- Practice security testing methodologies

## Tool Categories

### Scanning and Assessment Tools
- **[Cloud Scanners](scanners/)** - Multi-cloud security scanning tools
- **[Vulnerability Assessment](vulnerability/)** - Vulnerability scanning and assessment
- **[Configuration Audit](config-audit/)** - Configuration security auditing
- **[Compliance Checking](compliance/)** - Compliance validation tools

### Monitoring and Detection Tools
- **[Log Analysis](log-analysis/)** - Log analysis and monitoring
- **[Threat Detection](threat-detection/)** - Threat detection and alerting
- **[Network Monitoring](network-monitoring/)** - Network traffic analysis
- **[Anomaly Detection](anomaly-detection/)** - Behavioral analysis tools

### Automation and Response Tools
- **[Incident Response](incident-response/)** - Automated incident response scripts
- **[Security Automation](automation/)** - Security task automation
- **[Remediation Scripts](remediation/)** - Security issue remediation
- **[Orchestration](orchestration/)** - Security workflow orchestration

### Utility and Helper Tools
- **[Authentication Helpers](auth-helpers/)** - Authentication and access management
- **[Encryption Tools](encryption/)** - Data encryption and key management
- **[Reporting Tools](reporting/)** - Security reporting and visualization
- **[Testing Frameworks](testing/)** - Security testing frameworks

## Security Scanners

### 1. Multi-Cloud Security Scanner

#### Python Implementation
```python
# scanners/cloud_security_scanner.py
import json
import argparse
from datetime import datetime
import subprocess
import os

class CloudSecurityScanner:
    def __init__(self, cloud_provider, credentials_file=None):
        self.cloud_provider = cloud_provider.lower()
        self.credentials_file = credentials_file
        self.scan_results = {
            'scan_metadata': {
                'timestamp': datetime.utcnow().isoformat(),
                'cloud_provider': cloud_provider,
                'scanner_version': '1.0.0'
            },
            'findings': [],
            'summary': {}
        }
    
    def scan_azure_resources(self):
        """Scan Azure resources for security issues"""
        print("Scanning Azure resources...")
        
        # Check for public IP addresses
        public_ips_cmd = "az network public-ip list --output json"
        result = subprocess.run(public_ips_cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            public_ips = json.loads(result.stdout)
            for ip in public_ips:
                if ip.get('public_ip_allocation_method') == 'Static':
                    self.add_finding('PUBLIC_IP_STATIC', 'Medium', 
                        f"Static public IP found: {ip['public_ip_address']}", 
                        {'resource': ip.get('name'), 'ip': ip['public_ip_address']})
        
        # Check for unencrypted storage accounts
        storage_cmd = "az storage account list --output json"
        result = subprocess.run(storage_cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            storage_accounts = json.loads(result.stdout)
            for account in storage_accounts:
                if not account.get('encryption', {}).get('services', {}).get('blob', {}).get('enabled', False):
                    self.add_finding('UNENCRYPTED_STORAGE', 'High', 
                        f"Unencrypted storage account: {account['name']}", 
                        {'resource': account['name'], 'type': 'Storage Account'})
        
        # Check for missing NSGs
        vm_cmd = "az vm list --output json"
        result = subprocess.run(vm_cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            vms = json.loads(result.stdout)
            for vm in vms:
                nics = vm.get('network_profile', {}).get('network_interfaces', [])
                for nic in nics:
                    if not nic.get('network_security_group'):
                        self.add_finding('MISSING_NSG', 'High', 
                            f"VM without NSG: {vm['name']}", 
                            {'resource': vm['name'], 'type': 'Virtual Machine'})
    
    def scan_aws_resources(self):
        """Scan AWS resources for security issues"""
        print("Scanning AWS resources...")
        
        # Check for public S3 buckets
        s3_cmd = "aws s3api list-buckets --output json"
        result = subprocess.run(s3_cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            buckets = json.loads(result.stdout).get('Buckets', [])
            for bucket in buckets:
                bucket_name = bucket['Name']
                
                # Check bucket ACL
                acl_cmd = f"aws s3api get-bucket-acl --bucket {bucket_name}"
                acl_result = subprocess.run(acl_cmd, shell=True, capture_output=True, text=True)
                
                if acl_result.returncode == 0:
                    acl = json.loads(acl_result.stdout)
                    for grant in acl.get('Grants', []):
                        if grant.get('Grantee', {}).get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                            self.add_finding('PUBLIC_S3_BUCKET', 'High', 
                                f"Public S3 bucket: {bucket_name}", 
                                {'resource': bucket_name, 'type': 'S3 Bucket'})
        
        # Check for security groups open to the world
        sg_cmd = "aws ec2 describe-security-groups --output json"
        result = subprocess.run(sg_cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            security_groups = json.loads(result.stdout).get('SecurityGroups', [])
            for sg in security_groups:
                for rule in sg.get('IpPermissions', []):
                    for ip_range in rule.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            self.add_finding('OPEN_SECURITY_GROUP', 'Medium', 
                                f"Security group open to world: {sg['GroupId']}", 
                                {'resource': sg['GroupId'], 'type': 'Security Group'})
    
    def add_finding(self, finding_type, severity, description, details):
        """Add a security finding"""
        finding = {
            'id': f"{finding_type}_{len(self.scan_results['findings']) + 1}",
            'type': finding_type,
            'severity': severity,
            'description': description,
            'details': details,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        self.scan_results['findings'].append(finding)
    
    def generate_summary(self):
        """Generate scan summary"""
        findings = self.scan_results['findings']
        
        summary = {
            'total_findings': len(findings),
            'severity_breakdown': {
                'Critical': len([f for f in findings if f['severity'] == 'Critical']),
                'High': len([f for f in findings if f['severity'] == 'High']),
                'Medium': len([f for f in findings if f['severity'] == 'Medium']),
                'Low': len([f for f in findings if f['severity'] == 'Low'])
            },
            'finding_types': list(set([f['type'] for f in findings]))
        }
        
        self.scan_results['summary'] = summary
    
    def save_report(self, output_file):
        """Save scan report to file"""
        self.generate_summary()
        
        with open(output_file, 'w') as f:
            json.dump(self.scan_results, f, indent=2)
        
        print(f"Scan report saved to: {output_file}")
        print(f"Total findings: {self.scan_results['summary']['total_findings']}")
        print(f"Severity breakdown: {self.scan_results['summary']['severity_breakdown']}")
    
    def run_scan(self):
        """Run the security scan"""
        if self.cloud_provider == 'azure':
            self.scan_azure_resources()
        elif self.cloud_provider == 'aws':
            self.scan_aws_resources()
        else:
            print(f"Unsupported cloud provider: {self.cloud_provider}")
            return

def main():
    parser = argparse.ArgumentParser(description='Cloud Security Scanner')
    parser.add_argument('--provider', required=True, choices=['azure', 'aws'], 
                       help='Cloud provider to scan')
    parser.add_argument('--output', default='security_scan_report.json', 
                       help='Output file for scan report')
    parser.add_argument('--credentials', help='Credentials file path')
    
    args = parser.parse_args()
    
    scanner = CloudSecurityScanner(args.provider, args.credentials)
    scanner.run_scan()
    scanner.save_report(args.output)

if __name__ == '__main__':
    main()
```

### 2. Configuration Security Auditor

#### Bash Implementation
```bash
#!/bin/bash
# scanners/config_security_auditor.sh

CLOUD_PROVIDER=$1
OUTPUT_DIR=$2
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_FILE="${OUTPUT_DIR}/config_audit_${TIMESTAMP}.json"

mkdir -p "$OUTPUT_DIR"

echo "Starting configuration security audit for $CLOUD_PROVIDER"
echo "Report will be saved to: $REPORT_FILE"

# Initialize report
cat > "$REPORT_FILE" << EOF
{
  "audit_metadata": {
    "timestamp": "$(date -Iseconds)",
    "cloud_provider": "$CLOUD_PROVIDER",
    "auditor_version": "1.0.0"
  },
  "findings": [],
  "summary": {}
}
EOF

# Function to add finding
add_finding() {
    local finding_type=$1
    local severity=$2
    local description=$3
    local resource=$4
    
    # Create temporary JSON for the finding
    cat > /tmp/finding.json << FINDING_EOF
    {
      "id": "${finding_type}_${RANDOM}",
      "type": "$finding_type",
      "severity": "$severity",
      "description": "$description",
      "resource": "$resource",
      "timestamp": "$(date -Iseconds)"
    }
FINDING_EOF
    
    # Insert finding into report
    jq '.findings += [input]' /tmp/finding.json | \
    jq '.findings |= sort_by(.timestamp)' > /tmp/temp_report.json
    mv /tmp/temp_report.json "$REPORT_FILE"
}

# Function to update summary
update_summary() {
    local total_findings=$(jq '.findings | length' "$REPORT_FILE")
    local critical_count=$(jq '.findings | map(select(.severity == "Critical")) | length' "$REPORT_FILE")
    local high_count=$(jq '.findings | map(select(.severity == "High")) | length' "$REPORT_FILE")
    local medium_count=$(jq '.findings | map(select(.severity == "Medium")) | length' "$REPORT_FILE")
    local low_count=$(jq '.findings | map(select(.severity == "Low")) | length' "$REPORT_FILE")
    
    jq --arg total "$total_findings" \
       --arg critical "$critical_count" \
       --arg high "$high_count" \
       --arg medium "$medium_count" \
       --arg low "$low_count" \
       '.summary = {
           "total_findings": ($total | tonumber),
           "severity_breakdown": {
               "Critical": ($critical | tonumber),
               "High": ($high | tonumber),
               "Medium": ($medium | tonumber),
               "Low": ($low | tonumber)
           }
       }' "$REPORT_FILE" > /tmp/final_report.json
    
    mv /tmp/final_report.json "$REPORT_FILE"
}

# Azure Configuration Audit
if [ "$CLOUD_PROVIDER" = "azure" ]; then
    echo "Auditing Azure configurations..."
    
    # Check for unencrypted storage accounts
    echo "Checking storage account encryption..."
    az storage account list --output json | \
    jq -r '.[] | select(.encryption.services.blob.enabled == false) | 
    "\(.name) is not encrypted"' | \
    while read -r account; do
        if [ -n "$account" ]; then
            add_finding "UNENCRYPTED_STORAGE" "High" "Storage account not encrypted" "$account"
        fi
    done
    
    # Check for VMs without boot diagnostics
    echo "Checking VM boot diagnostics..."
    az vm list --output json | \
    jq -r '.[] | select(.diagnosticsProfile.bootDiagnostics.enabled == false) | 
    "\(.name) has boot diagnostics disabled"' | \
    while read -r vm; do
        if [ -n "$vm" ]; then
            add_finding "DISABLED_BOOT_DIAGNOSTICS" "Medium" "VM boot diagnostics disabled" "$vm"
        fi
    done
    
    # Check for missing tags
    echo "Checking resource tagging..."
    az group list --output json | \
    jq -r '.[] | select((.tags | length) < 2) | 
    "\(.name) has insufficient tags"' | \
    while read -r group; do
        if [ -n "$group" ]; then
            add_finding "INSUFFICIENT_TAGS" "Low" "Resource group has insufficient tags" "$group"
        fi
    done
fi

# AWS Configuration Audit
if [ "$CLOUD_PROVIDER" = "aws" ]; then
    echo "Auditing AWS configurations..."
    
    # Check for S3 buckets without versioning
    echo "Checking S3 bucket versioning..."
    aws s3api list-buckets --output json | \
    jq -r '.Buckets[] | .Name' | \
    while read -r bucket; do
        versioning=$(aws s3api get-bucket-versioning --bucket "$bucket" --output json | \
                   jq -r '.Status')
        if [ "$versioning" = "Disabled" ]; then
            add_finding "DISABLED_VERSIONING" "Medium" "S3 bucket versioning disabled" "$bucket"
        fi
    done
    
    # Check for EBS volumes without encryption
    echo "Checking EBS volume encryption..."
    aws ec2 describe-volumes --output json | \
    jq -r '.Volumes[] | select(.Encrypted == false) | 
    "\(.VolumeId) is not encrypted"' | \
    while read -r volume; do
        if [ -n "$volume" ]; then
            add_finding "UNENCRYPTED_EBS" "High" "EBS volume not encrypted" "$volume"
        fi
    done
    
    # Check for IAM users with console access
    echo "Checking IAM user console access..."
    aws iam list-users --output json | \
    jq -r '.Users[] | select(.PasswordLastUsed == null) | 
    "\(.UserName) has never used console access"' | \
    while read -r user; do
        if [ -n "$user" ]; then
            add_finding "UNUSED_CONSOLE_ACCESS" "Low" "IAM user has never used console access" "$user"
        fi
    done
fi

# Update summary
update_summary

echo "Configuration audit completed"
echo "Report saved to: $REPORT_FILE"
echo "Summary:"
jq '.summary' "$REPORT_FILE"
```

## Monitoring and Detection Tools

### 1. Real-time Threat Detection

#### Python Implementation
```python
# threat-detection/real_time_detector.py
import json
import time
import threading
from datetime import datetime, timedelta
import requests
from collections import defaultdict, deque

class RealTimeThreatDetector:
    def __init__(self, config_file):
        self.config = self.load_config(config_file)
        self.alert_queue = deque(maxlen=1000)
        self.threat_indicators = {}
        self.running = False
        
    def load_config(self, config_file):
        """Load detector configuration"""
        with open(config_file, 'r') as f:
            return json.load(f)
    
    def analyze_log_stream(self, log_source):
        """Analyze log stream for threats"""
        print(f"Starting log analysis for: {log_source}")
        
        while self.running:
            try:
                # Get new log entries
                logs = self.get_logs(log_source)
                
                for log_entry in logs:
                    threats = self.analyze_entry(log_entry)
                    
                    for threat in threats:
                        self.process_threat(threat)
                
                time.sleep(self.config.get('scan_interval', 5))
                
            except Exception as e:
                print(f"Error analyzing logs: {e}")
                time.sleep(10)
    
    def analyze_entry(self, log_entry):
        """Analyze individual log entry for threats"""
        threats = []
        message = log_entry.get('message', '')
        timestamp = log_entry.get('timestamp', datetime.utcnow())
        
        # Check for known threat patterns
        for pattern_name, pattern_config in self.config.get('threat_patterns', {}).items():
            pattern = pattern_config.get('pattern')
            severity = pattern_config.get('severity', 'Medium')
            
            if self.matches_pattern(message, pattern):
                threat = {
                    'id': f"{pattern_name}_{int(time.time())}",
                    'type': pattern_name,
                    'severity': severity,
                    'timestamp': timestamp,
                    'source': log_entry.get('source', 'unknown'),
                    'details': {
                        'message': message,
                        'pattern_matched': pattern,
                        'log_entry': log_entry
                    }
                }
                threats.append(threat)
        
        return threats
    
    def matches_pattern(self, message, pattern):
        """Check if message matches threat pattern"""
        if isinstance(pattern, str):
            return pattern.lower() in message.lower()
        elif isinstance(pattern, dict):
            # Handle complex patterns
            if 'regex' in pattern:
                import re
                return bool(re.search(pattern['regex'], message, re.IGNORECASE))
            elif 'keywords' in pattern:
                return any(keyword.lower() in message.lower() for keyword in pattern['keywords'])
        return False
    
    def process_threat(self, threat):
        """Process detected threat"""
        print(f"Threat detected: {threat['type']} - {threat['severity']}")
        
        # Add to alert queue
        self.alert_queue.append(threat)
        
        # Update threat indicators
        self.update_threat_indicators(threat)
        
        # Send alert
        self.send_alert(threat)
    
    def update_threat_indicators(self, threat):
        """Update threat indicators"""
        threat_type = threat['type']
        
        if threat_type not in self.threat_indicators:
            self.threat_indicators[threat_type] = {
                'count': 0,
                'first_seen': threat['timestamp'],
                'last_seen': threat['timestamp'],
                'severity_distribution': defaultdict(int)
            }
        
        self.threat_indicators[threat_type]['count'] += 1
        self.threat_indicators[threat_type]['last_seen'] = threat['timestamp']
        self.threat_indicators[threat_type]['severity_distribution'][threat['severity']] += 1
    
    def send_alert(self, threat):
        """Send threat alert"""
        alert = {
            'alert_id': f"ALERT_{threat['id']}",
            'threat_type': threat['type'],
            'severity': threat['severity'],
            'timestamp': threat['timestamp'],
            'description': f"Threat detected: {threat['type']}",
            'details': threat['details'],
            'action_required': self.get_action_required(threat['severity'])
        }
        
        # Send to alerting system
        alert_endpoint = self.config.get('alert_endpoint')
        if alert_endpoint:
            try:
                response = requests.post(alert_endpoint, json=alert, timeout=10)
                if response.status_code == 200:
                    print(f"Alert sent successfully: {alert['alert_id']}")
                else:
                    print(f"Failed to send alert: {response.status_code}")
            except Exception as e:
                print(f"Error sending alert: {e}")
    
    def get_action_required(self, severity):
        """Get required action based on severity"""
        actions = {
            'Critical': 'Immediate investigation and containment required',
            'High': 'Investigation required within 1 hour',
            'Medium': 'Investigation required within 4 hours',
            'Low': 'Investigation required within 24 hours'
        }
        return actions.get(severity, 'Review required')
    
    def get_logs(self, log_source):
        """Get logs from source"""
        # This would integrate with actual log sources
        # For demonstration, return sample logs
        return [
            {
                'timestamp': datetime.utcnow(),
                'source': log_source,
                'message': 'Failed login attempt for user admin from IP 192.168.1.100'
            },
            {
                'timestamp': datetime.utcnow(),
                'source': log_source,
                'message': 'SQL injection attempt detected in web application'
            }
        ]
    
    def start_monitoring(self):
        """Start real-time monitoring"""
        self.running = True
        
        # Start monitoring threads for each log source
        log_sources = self.config.get('log_sources', [])
        threads = []
        
        for source in log_sources:
            thread = threading.Thread(target=self.analyze_log_stream, args=(source,))
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
        print(f"Started monitoring {len(threads)} log sources")
        
        # Keep main thread alive
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            print("Stopping monitoring...")
            self.running = False
        
        # Wait for threads to finish
        for thread in threads:
            thread.join()
    
    def generate_threat_report(self):
        """Generate threat detection report"""
        report = {
            'report_metadata': {
                'timestamp': datetime.utcnow().isoformat(),
                'detector_version': '1.0.0'
            },
            'threat_indicators': self.threat_indicators,
            'recent_alerts': list(self.alert_queue)[-10:],  # Last 10 alerts
            'statistics': self.calculate_statistics()
        }
        
        return report
    
    def calculate_statistics(self):
        """Calculate detection statistics"""
        total_alerts = len(self.alert_queue)
        
        severity_counts = defaultdict(int)
        for alert in self.alert_queue:
            severity_counts[alert['severity']] += 1
        
        return {
            'total_alerts': total_alerts,
            'severity_distribution': dict(severity_counts),
            'top_threat_types': self.get_top_threat_types(),
            'detection_rate': self.calculate_detection_rate()
        }
    
    def get_top_threat_types(self):
        """Get top threat types"""
        type_counts = defaultdict(int)
        for alert in self.alert_queue:
            type_counts[alert['type']] += 1
        
        # Return top 5 threat types
        sorted_types = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)
        return sorted_types[:5]
    
    def calculate_detection_rate(self):
        """Calculate threat detection rate"""
        # This would be calculated based on actual metrics
        # For demonstration, return a sample rate
        return 15.5  # threats per hour

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Real-time Threat Detector')
    parser.add_argument('--config', required=True, help='Configuration file path')
    parser.add_argument('--report', help='Generate threat report and exit')
    
    args = parser.parse_args()
    
    detector = RealTimeThreatDetector(args.config)
    
    if args.report:
        report = detector.generate_threat_report()
        print(json.dumps(report, indent=2))
    else:
        detector.start_monitoring()

if __name__ == '__main__':
    main()
```

## Security Automation Tools

### 1. Automated Remediation Framework

#### Python Implementation
```python
# automation/remediation_framework.py
import json
import time
from datetime import datetime
import subprocess
import threading

class SecurityRemediationFramework:
    def __init__(self, config_file):
        self.config = self.load_config(config_file)
        self.remediation_queue = []
        self.running = False
        self.remediation_history = []
        
    def load_config(self, config_file):
        """Load remediation configuration"""
        with open(config_file, 'r') as f:
            return json.load(f)
    
    def add_remediation_task(self, task):
        """Add remediation task to queue"""
        self.remediation_queue.append({
            'id': f"TASK_{len(self.remediation_queue) + 1}",
            'type': task['type'],
            'severity': task.get('severity', 'Medium'),
            'resource': task['resource'],
            'description': task['description'],
            'timestamp': datetime.utcnow().isoformat(),
            'status': 'queued',
            'attempts': 0,
            'max_attempts': 3
        })
    
    def process_remediation_queue(self):
        """Process remediation queue"""
        while self.running or self.remediation_queue:
            if not self.remediation_queue:
                time.sleep(1)
                continue
            
            task = self.remediation_queue.pop(0)
            self.execute_remediation(task)
            
            time.sleep(2)  # Delay between remediations
    
    def execute_remediation(self, task):
        """Execute remediation task"""
        print(f"Executing remediation: {task['type']} for {task['resource']}")
        
        task['status'] = 'in_progress'
        task['attempts'] += 1
        
        try:
            if task['type'] == 'disable_public_access':
                result = self.disable_public_access(task['resource'])
            elif task['type'] == 'enable_encryption':
                result = self.enable_encryption(task['resource'])
            elif task['type'] == 'configure_backup':
                result = self.configure_backup(task['resource'])
            elif task['type'] == 'update_nsg_rules':
                result = self.update_nsg_rules(task['resource'])
            else:
                result = {'success': False, 'message': f"Unknown remediation type: {task['type']}"}
            
            if result['success']:
                task['status'] = 'completed'
                task['completed_at'] = datetime.utcnow().isoformat()
                print(f"Remediation completed successfully")
            else:
                task['status'] = 'failed'
                task['error'] = result['message']
                print(f"Remediation failed: {result['message']}")
                
                # Retry logic
                if task['attempts'] < task['max_attempts']:
                    self.remediation_queue.append(task)
                    print(f"Scheduling retry attempt {task['attempts'] + 1}")
            
        except Exception as e:
            task['status'] = 'failed'
            task['error'] = str(e)
            print(f"Remediation error: {e}")
        
        # Add to history
        self.remediation_history.append(task.copy())
    
    def disable_public_access(self, resource):
        """Disable public access for resource"""
        resource_type = resource.get('type')
        resource_name = resource.get('name')
        
        if resource_type == 'storage_account':
            cmd = f"az storage account update --name {resource_name} --allow-blob-public-access false"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                return {'success': True, 'message': 'Public access disabled'}
            else:
                return {'success': False, 'message': result.stderr}
        
        elif resource_type == 'vm':
            cmd = f"az vm stop --name {resource_name}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                return {'success': True, 'message': 'VM stopped'}
            else:
                return {'success': False, 'message': result.stderr}
        
        else:
            return {'success': False, 'message': f"Unsupported resource type: {resource_type}"}
    
    def enable_encryption(self, resource):
        """Enable encryption for resource"""
        resource_type = resource.get('type')
        resource_name = resource.get('name')
        
        if resource_type == 'storage_account':
            cmd = f"az storage account encryption update --account-name {resource_name} --services blob table file"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                return {'success': True, 'message': 'Encryption enabled'}
            else:
                return {'success': False, 'message': result.stderr}
        
        elif resource_type == 'vm_disk':
            cmd = f"az vm disk update --name {resource_name} --encryption-type EncryptionAtRestWithPlatformKey"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                return {'success': True, 'message': 'Disk encryption enabled'}
            else:
                return {'success': False, 'message': result.stderr}
        
        else:
            return {'success': False, 'message': f"Unsupported resource type: {resource_type}"}
    
    def configure_backup(self, resource):
        """Configure backup for resource"""
        resource_type = resource.get('type')
        resource_name = resource.get('name')
        
        if resource_type == 'vm':
            cmd = f"az backup protection enable-for-vm --vm {resource_name} --backup-policy DefaultPolicy"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                return {'success': True, 'message': 'Backup configured'}
            else:
                return {'success': False, 'message': result.stderr}
        
        else:
            return {'success': False, 'message': f"Unsupported resource type: {resource_type}"}
    
    def update_nsg_rules(self, resource):
        """Update NSG rules"""
        nsg_name = resource.get('name')
        rules = resource.get('rules', [])
        
        for rule in rules:
            rule_name = rule.get('name')
            action = rule.get('action', 'deny')
            
            cmd = f"az network nsg rule create --nsg-name {nsg_name} --name {rule_name} --access {action}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode != 0:
                return {'success': False, 'message': result.stderr}
        
        return {'success': True, 'message': 'NSG rules updated'}
    
    def start_automation(self):
        """Start automated remediation"""
        self.running = True
        
        # Start remediation thread
        remediation_thread = threading.Thread(target=self.process_remediation_queue)
        remediation_thread.daemon = True
        remediation_thread.start()
        
        print("Automated remediation started")
        
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            print("Stopping automated remediation...")
            self.running = False
        
        remediation_thread.join()
    
    def generate_remediation_report(self):
        """Generate remediation report"""
        report = {
            'report_metadata': {
                'timestamp': datetime.utcnow().isoformat(),
                'automation_version': '1.0.0'
            },
            'statistics': self.calculate_statistics(),
            'recent_tasks': self.remediation_history[-20:],  # Last 20 tasks
            'success_rate': self.calculate_success_rate()
        }
        
        return report
    
    def calculate_statistics(self):
        """Calculate remediation statistics"""
        total_tasks = len(self.remediation_history)
        
        if total_tasks == 0:
            return {
                'total_tasks': 0,
                'success_rate': 0,
                'failure_rate': 0,
                'retry_rate': 0
            }
        
        successful_tasks = len([t for t in self.remediation_history if t['status'] == 'completed'])
        failed_tasks = len([t for t in self.remediation_history if t['status'] == 'failed'])
        retry_tasks = len([t for t in self.remediation_history if t['attempts'] > 1])
        
        return {
            'total_tasks': total_tasks,
            'successful_tasks': successful_tasks,
            'failed_tasks': failed_tasks,
            'retry_tasks': retry_tasks,
            'success_rate': (successful_tasks / total_tasks) * 100,
            'failure_rate': (failed_tasks / total_tasks) * 100,
            'retry_rate': (retry_tasks / total_tasks) * 100
        }
    
    def calculate_success_rate(self):
        """Calculate success rate"""
        stats = self.calculate_statistics()
        return stats.get('success_rate', 0)

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Security Remediation Framework')
    parser.add_argument('--config', required=True, help='Configuration file path')
    parser.add_argument('--report', help='Generate remediation report and exit')
    parser.add_argument('--task', help='Add remediation task (JSON format)')
    
    args = parser.parse_args()
    
    framework = SecurityRemediationFramework(args.config)
    
    if args.report:
        report = framework.generate_remediation_report()
        print(json.dumps(report, indent=2))
    elif args.task:
        task = json.loads(args.task)
        framework.add_remediation_task(task)
        print(f"Task added to queue: {task['type']}")
    else:
        framework.start_automation()

if __name__ == '__main__':
    main()
```

## Usage Examples

### 1. Running Security Scans
```bash
# Run Azure security scan
python3 scanners/cloud_security_scanner.py --provider azure --output azure_scan_report.json

# Run AWS security scan
python3 scanners/cloud_security_scanner.py --provider aws --output aws_scan_report.json

# Run configuration audit
bash scanners/config_security_auditor.sh azure /tmp/audit_reports
```

### 2. Starting Threat Detection
```bash
# Create configuration file
cat > threat_detector_config.json << EOF
{
  "scan_interval": 5,
  "alert_endpoint": "https://your-alerting-system.com/api/alerts",
  "log_sources": ["auth_logs", "web_logs", "system_logs"],
  "threat_patterns": {
    "failed_login": {
      "pattern": "failed.*login",
      "severity": "Medium"
    },
    "sql_injection": {
      "pattern": {
        "regex": "(?i)(union|select|insert|update|delete).*from",
        "keywords": ["sql injection", "union select"]
      },
      "severity": "High"
    },
    "privilege_escalation": {
      "pattern": "sudo|su|escalat",
      "severity": "Critical"
    }
  }
}
EOF

# Start real-time threat detection
python3 threat-detection/real_time_detector.py --config threat_detector_config.json
```

### 3. Automated Remediation
```bash
# Create remediation configuration
cat > remediation_config.json << EOF
{
  "remediation_rules": {
    "public_storage": {
      "action": "disable_public_access",
      "auto_execute": true
    },
    "unencrypted_resources": {
      "action": "enable_encryption",
      "auto_execute": true
    },
    "missing_backup": {
      "action": "configure_backup",
      "auto_execute": false
    }
  }
}
EOF

# Start automated remediation
python3 automation/remediation_framework.py --config remediation_config.json
```

## Best Practices

### 1. Tool Development
- **Error Handling**: Implement comprehensive error handling
- **Logging**: Use structured logging for debugging
- **Configuration**: Use configuration files for flexibility
- **Security**: Follow secure coding practices
- **Testing**: Test tools thoroughly before deployment

### 2. Tool Usage
- **Testing Environment**: Test in non-production environments
- **Permissions**: Use least privilege access
- **Monitoring**: Monitor tool performance and effectiveness
- **Documentation**: Document tool usage and configuration
- **Regular Updates**: Keep tools updated with latest security practices

### 3. Integration
- **API Integration**: Use standard APIs for integration
- **Data Formats**: Use standard data formats (JSON, XML)
- **Authentication**: Use secure authentication methods
- **Rate Limiting**: Implement rate limiting for API calls
- **Error Recovery**: Implement error recovery mechanisms

---

**Build comprehensive security tools** by using these scripts and frameworks for your cloud security operations.
