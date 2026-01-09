# Incident Response Procedures

## Overview

Incident Response (IR) is the organized approach to addressing and managing the aftermath of a security breach or cyberattack. This guide covers IR procedures, playbooks, and best practices for cloud environments.

## Learning Objectives

By mastering incident response procedures, you will:
- Understand incident response frameworks and methodologies
- Develop comprehensive IR playbooks for common scenarios
- Implement incident detection and analysis capabilities
- Build effective incident communication protocols
- Create post-incident review and improvement processes
- Establish IR team structures and responsibilities

## Incident Response Framework

### NIST Incident Response Lifecycle
```
Preparation -> Detection -> Analysis -> Containment -> Eradication -> Recovery -> Lessons Learned
     |             |           |            |            |           |              |
     |             |           |            |            |           |              v
     |             |           |            |            |           |    Continuous Improvement
     |             |           |            |            |           |
     |             |           |            |            |           v
     |             |           |            |            |    Post-Incident Activities
     |             |           |            |            |
     |             |           |            |            v
     |             |           |            |    Recovery Activities
     |             |           |            |
     |             |           |            v
     |             |           |    Eradication Activities
     |             |           |
     |             |           v
     |             |    Containment Activities
     |             |
     |             v
     |    Analysis Activities
     |
     v
Detection Activities
```

### Incident Classification

#### Severity Levels
- **Critical**: Business impact, data breach, system compromise
- **High**: Significant service degradation, limited data exposure
- **Medium**: Service impact, potential data exposure
- **Low**: Minimal impact, security incident only

#### Incident Categories
- **Malware**: Virus, ransomware, spyware infections
- **Network**: DDoS attacks, network intrusions
- **Data**: Data breaches, data loss, unauthorized access
- **Application**: Web application attacks, API abuse
- **Insider**: Insider threats, privilege abuse
- **Physical**: Physical security breaches

## Incident Response Team Structure

### Core Roles and Responsibilities

#### Incident Commander (IC)
- Overall incident coordination
- Decision-making authority
- External communication
- Resource allocation

#### Security Analyst
- Technical investigation
- Evidence collection
- Malware analysis
- Forensic examination

#### Communications Lead
- Internal communications
- External notifications
- Media relations
- Stakeholder updates

#### Legal/Compliance Officer
- Legal guidance
- Regulatory compliance
- Evidence handling
- Reporting requirements

#### IT/Operations Lead
- System restoration
- Infrastructure support
- Backup recovery
- Service restoration

## Incident Detection and Analysis

### 1. Detection Mechanisms

#### Automated Detection Systems
```python
# incident_detection.py
import re
import json
from datetime import datetime, timedelta
from collections import defaultdict

class IncidentDetector:
    def __init__(self):
        self.detection_rules = {
            'failed_login_threshold': {
                'pattern': 'failed_login',
                'threshold': 5,
                'timeframe': 300,  # 5 minutes
                'severity': 'medium'
            },
            'suspicious_file_access': {
                'pattern': r'access.*sensitive.*file',
                'threshold': 1,
                'timeframe': 60,
                'severity': 'high'
            },
            'unusual_data_transfer': {
                'pattern': r'data.*transfer.*large',
                'threshold': 1,
                'timeframe': 300,
                'severity': 'high'
            },
            'privilege_escalation': {
                'pattern': r'sudo|su|escalat',
                'threshold': 1,
                'timeframe': 60,
                'severity': 'critical'
            }
        }
        
        self.event_buffer = []
        self.active_incidents = []
    
    def process_log_entry(self, log_entry):
        """Process individual log entry"""
        timestamp = log_entry.get('timestamp', datetime.utcnow())
        message = log_entry.get('message', '')
        source = log_entry.get('source', 'unknown')
        
        # Check against detection rules
        for rule_name, rule_config in self.detection_rules.items():
            if self.matches_pattern(message, rule_config['pattern']):
                event = {
                    'timestamp': timestamp,
                    'rule': rule_name,
                    'message': message,
                    'source': source,
                    'severity': rule_config['severity']
                }
                
                self.event_buffer.append(event)
                self.check_thresholds(rule_name, rule_config)
        
        # Clean old events
        self.cleanup_old_events()
    
    def matches_pattern(self, message, pattern):
        """Check if message matches pattern"""
        if isinstance(pattern, str):
            return pattern in message.lower()
        elif hasattr(pattern, 'search'):
            return bool(pattern.search(message, re.IGNORECASE))
        return False
    
    def check_thresholds(self, rule_name, rule_config):
        """Check if threshold is exceeded"""
        current_time = datetime.utcnow()
        threshold_time = current_time - timedelta(seconds=rule_config['timeframe'])
        
        # Count matching events in timeframe
        matching_events = [
            event for event in self.event_buffer
            if event['rule'] == rule_name and 
               event['timestamp'] >= threshold_time
        ]
        
        if len(matching_events) >= rule_config['threshold']:
            self.create_incident(rule_name, matching_events, rule_config['severity'])
    
    def create_incident(self, rule_name, events, severity):
        """Create incident from detected events"""
        incident = {
            'id': f"INC-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            'timestamp': datetime.utcnow(),
            'rule': rule_name,
            'severity': severity,
            'events': events,
            'status': 'detected',
            'description': f"Incident detected: {rule_name}"
        }
        
        self.active_incidents.append(incident)
        self.send_alert(incident)
        
        return incident
    
    def send_alert(self, incident):
        """Send incident alert"""
        alert = {
            'incident_id': incident['id'],
            'severity': incident['severity'],
            'description': incident['description'],
            'timestamp': incident['timestamp'],
            'action_required': 'Investigate immediately'
        }
        
        # Send to alerting system
        print(f"ALERT: {json.dumps(alert, indent=2)}")
        
        # Log alert
        with open('/var/log/incident_alerts.log', 'a') as f:
            f.write(json.dumps(alert) + '\n')
    
    def cleanup_old_events(self):
        """Remove old events from buffer"""
        cutoff_time = datetime.utcnow() - timedelta(hours=1)
        self.event_buffer = [
            event for event in self.event_buffer
            if event['timestamp'] >= cutoff_time
        ]
    
    def get_active_incidents(self):
        """Get list of active incidents"""
        return self.active_incidents
    
    def update_incident_status(self, incident_id, status, notes=None):
        """Update incident status"""
        for incident in self.active_incidents:
            if incident['id'] == incident_id:
                incident['status'] = status
                incident['last_updated'] = datetime.utcnow()
                if notes:
                    incident.setdefault('notes', []).append({
                        'timestamp': datetime.utcnow(),
                        'note': notes
                    })
                break

# Usage
detector = IncidentDetector()

# Sample log entries
log_entries = [
    {
        'timestamp': datetime.utcnow(),
        'message': 'Failed login attempt for user admin',
        'source': 'auth-service'
    },
    {
        'timestamp': datetime.utcnow(),
        'message': 'Failed login attempt for user admin',
        'source': 'auth-service'
    },
    {
        'timestamp': datetime.utcnow(),
        'message': 'Privilege escalation attempt: sudo su',
        'source': 'system'
    }
]

for entry in log_entries:
    detector.process_log_entry(entry)

active_incidents = detector.get_active_incidents()
print(f"Active incidents: {len(active_incidents)}")
```

### 2. Incident Analysis Framework

#### Triage and Assessment
```python
# incident_triage.py
import json
from datetime import datetime

class IncidentTriage:
    def __init__(self):
        self.triage_questions = {
            'business_impact': [
                'Is critical business service affected?',
                'Is customer data compromised?',
                'Is revenue impacted?',
                'Is brand reputation at risk?'
            ],
            'technical_impact': [
                'Are systems compromised?',
                'Is data exfiltrated?',
                'Are attackers still active?',
                'Is malware present?'
            ],
            'scope': [
                'How many systems affected?',
                'How many users affected?',
                'What data types involved?',
                'What geographic regions affected?'
            ]
        }
    
    def conduct_triage(self, incident):
        """Conduct incident triage"""
        triage_result = {
            'incident_id': incident['id'],
            'triage_time': datetime.utcnow(),
            'initial_severity': incident['severity'],
            'assessments': {},
            'recommended_actions': [],
            'escalation_required': False
        }
        
        # Business impact assessment
        business_score = self.assess_business_impact(incident)
        triage_result['assessments']['business_impact'] = business_score
        
        # Technical impact assessment
        technical_score = self.assess_technical_impact(incident)
        triage_result['assessments']['technical_impact'] = technical_score
        
        # Scope assessment
        scope_score = self.assess_scope(incident)
        triage_result['assessments']['scope'] = scope_score
        
        # Calculate overall severity
        overall_score = (business_score + technical_score + scope_score) / 3
        triage_result['calculated_severity'] = self.calculate_severity(overall_score)
        
        # Generate recommendations
        triage_result['recommended_actions'] = self.generate_recommendations(
            triage_result['assessments']
        )
        
        # Determine escalation
        triage_result['escalation_required'] = self.determine_escalation(
            triage_result['calculated_severity']
        )
        
        return triage_result
    
    def assess_business_impact(self, incident):
        """Assess business impact"""
        score = 0
        
        # Check for critical service impact
        if 'critical' in incident.get('description', '').lower():
            score += 3
        
        # Check for data compromise
        if 'data' in incident.get('description', '').lower() and \
           'compromise' in incident.get('description', '').lower():
            score += 3
        
        # Check for revenue impact
        if 'revenue' in incident.get('description', '').lower() or \
           'financial' in incident.get('description', '').lower():
            score += 2
        
        return min(score, 10)
    
    def assess_technical_impact(self, incident):
        """Assess technical impact"""
        score = 0
        
        # Check for system compromise
        if 'compromise' in incident.get('description', '').lower():
            score += 3
        
        # Check for data exfiltration
        if 'exfiltrat' in incident.get('description', '').lower():
            score += 3
        
        # Check for active attacker
        if 'active' in incident.get('description', '').lower():
            score += 2
        
        # Check for malware
        if 'malware' in incident.get('description', '').lower():
            score += 2
        
        return min(score, 10)
    
    def assess_scope(self, incident):
        """Assess incident scope"""
        score = 0
        
        # Count affected systems
        affected_systems = len(incident.get('affected_systems', []))
        score += min(affected_systems, 5)
        
        # Count affected users
        affected_users = incident.get('affected_users', 0)
        if affected_users > 1000:
            score += 3
        elif affected_users > 100:
            score += 2
        elif affected_users > 10:
            score += 1
        
        return min(score, 10)
    
    def calculate_severity(self, score):
        """Calculate severity from score"""
        if score >= 8:
            return 'critical'
        elif score >= 6:
            return 'high'
        elif score >= 4:
            return 'medium'
        else:
            return 'low'
    
    def generate_recommendations(self, assessments):
        """Generate triage recommendations"""
        recommendations = []
        
        business_impact = assessments.get('business_impact', 0)
        technical_impact = assessments.get('technical_impact', 0)
        scope = assessments.get('scope', 0)
        
        if business_impact >= 7:
            recommendations.append('Immediate executive notification required')
            recommendations.append('Prepare customer communications')
        
        if technical_impact >= 7:
            recommendations.append('Isolate affected systems')
            recommendations.append('Preserve forensic evidence')
        
        if scope >= 7:
            recommendations.append('Mobilize full incident response team')
            recommendations.append('Engage external security experts')
        
        return recommendations
    
    def determine_escalation(self, severity):
        """Determine if escalation is required"""
        return severity in ['critical', 'high']

# Usage
triage = IncidentTriage()

sample_incident = {
    'id': 'INC-20240101001',
    'description': 'Critical data breach detected - customer data compromised',
    'severity': 'high',
    'affected_systems': ['web-server-1', 'database-1'],
    'affected_users': 5000
}

triage_result = triage.conduct_triage(sample_incident)
print(json.dumps(triage_result, indent=2))
```

## Incident Response Playbooks

### 1. Data Breach Response Playbook

#### Phase 1: Immediate Response (0-2 hours)
```bash
#!/bin/bash
# data_breach_immediate_response.sh

INCIDENT_ID=$1
SEVERITY=$2

echo "Starting Data Breach Immediate Response for Incident: $INCIDENT_ID"

# Step 1: Incident Commander Assignment
echo "Assigning Incident Commander..."
echo "IC: $(date): Incident $INCIDENT_ID assigned to Security Team Lead" >> /var/log/incident.log

# Step 2: Initial Assessment
echo "Conducting initial assessment..."
python3 scripts/initial_assessment.py --incident-id $INCIDENT_ID

# Step 3: Evidence Preservation
echo "Preserving evidence..."
mkdir -p /evidence/$INCIDENT_ID
cp -r /var/log/* /evidence/$INCIDENT_ID/
tar -czf /evidence/$INCIDENT_ID/system_snapshot_$(date +%Y%m%d_%H%M%S).tar.gz /etc /var/log

# Step 4: Initial Containment
echo "Implementing initial containment..."
# Block suspicious IPs
iptables -A INPUT -s SUSPICIOUS_IP -j DROP

# Disable compromised accounts
python3 scripts/disable_compromised_accounts.py --incident-id $INCIDENT_ID

# Step 5: Stakeholder Notification
echo "Notifying stakeholders..."
python3 scripts/notify_stakeholders.py --incident-id $INCIDENT_ID --severity $SEVERITY

# Step 6: Documentation
echo "Creating incident log..."
cat > /evidence/$INCIDENT_ID/incident_log.md << EOF
# Data Breach Incident Log

## Incident Details
- **Incident ID**: $INCIDENT_ID
- **Date**: $(date)
- **Severity**: $SEVERITY
- **Assigned IC**: Security Team Lead

## Timeline
- $(date): Incident detected
- $(date): Immediate response initiated
- $(date): Initial containment implemented

## Actions Taken
1. Incident Commander assigned
2. Initial assessment conducted
3. Evidence preserved
4. Initial containment implemented
5. Stakeholders notified

## Next Steps
1. Detailed investigation
2. Full containment
3. Eradication
4. Recovery
5. Post-incident review
EOF

echo "Data Breach Immediate Response completed for Incident: $INCIDENT_ID"
```

#### Phase 2: Investigation and Analysis (2-24 hours)
```python
# data_breach_investigation.py
import json
import subprocess
from datetime import datetime

class DataBreachInvestigator:
    def __init__(self, incident_id):
        self.incident_id = incident_id
        self.evidence_dir = f"/evidence/{incident_id}"
        self.investigation_log = []
    
    def log_investigation_step(self, step, details):
        """Log investigation step"""
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'step': step,
            'details': details
        }
        self.investigation_log.append(log_entry)
        
        with open(f"{self.evidence_dir}/investigation_log.json", 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
    
    def analyze_network_logs(self):
        """Analyze network logs for suspicious activity"""
        self.log_investigation_step("Network Log Analysis", "Starting network log analysis")
        
        # Analyze firewall logs
        firewall_cmd = f"grep -i 'deny\\|drop' /var/log/firewall.log | tail -100"
        firewall_result = subprocess.run(firewall_cmd, shell=True, capture_output=True, text=True)
        
        # Analyze web server logs
        webserver_cmd = f"grep -i 'error\\|forbidden' /var/log/nginx/access.log | tail -100"
        webserver_result = subprocess.run(webserver_cmd, shell=True, capture_output=True, text=True)
        
        analysis_results = {
            'firewall_blocks': firewall_result.stdout,
            'webserver_errors': webserver_result.stdout
        }
        
        with open(f"{self.evidence_dir}/network_analysis.json", 'w') as f:
            json.dump(analysis_results, f, indent=2)
        
        self.log_investigation_step("Network Log Analysis", "Network log analysis completed")
        return analysis_results
    
    def analyze_system_logs(self):
        """Analyze system logs for compromise indicators"""
        self.log_investigation_step("System Log Analysis", "Starting system log analysis")
        
        # Check for suspicious login attempts
        login_cmd = "grep -i 'failed\\|invalid' /var/log/auth.log | tail -50"
        login_result = subprocess.run(login_cmd, shell=True, capture_output=True, text=True)
        
        # Check for privilege escalation
        sudo_cmd = "grep -i 'sudo\\|su' /var/log/auth.log | tail -50"
        sudo_result = subprocess.run(sudo_cmd, shell=True, capture_output=True, text=True)
        
        # Check for unusual processes
        process_cmd = "ps aux --sort=-%cpu | head -20"
        process_result = subprocess.run(process_cmd, shell=True, capture_output=True, text=True)
        
        analysis_results = {
            'suspicious_logins': login_result.stdout,
            'privilege_escalation': sudo_result.stdout,
            'unusual_processes': process_result.stdout
        }
        
        with open(f"{self.evidence_dir}/system_analysis.json", 'w') as f:
            json.dump(analysis_results, f, indent=2)
        
        self.log_investigation_step("System Log Analysis", "System log analysis completed")
        return analysis_results
    
    def analyze_file_system(self):
        """Analyze file system for unauthorized changes"""
        self.log_investigation_step("File System Analysis", "Starting file system analysis")
        
        # Check for modified files in last 24 hours
        modified_cmd = "find / -type f -mtime -1 -ls"
        modified_result = subprocess.run(modified_cmd, shell=True, capture_output=True, text=True)
        
        # Check for suspicious files
        suspicious_cmd = "find / -name '*.tmp' -o -name '.*' -type f | head -20"
        suspicious_result = subprocess.run(suspicious_cmd, shell=True, capture_output=True, text=True)
        
        # Check for large file transfers
        large_files_cmd = "find / -size +100M -type f -ls"
        large_files_result = subprocess.run(large_files_cmd, shell=True, capture_output=True, text=True)
        
        analysis_results = {
            'modified_files': modified_result.stdout,
            'suspicious_files': suspicious_result.stdout,
            'large_files': large_files_result.stdout
        }
        
        with open(f"{self.evidence_dir}/filesystem_analysis.json", 'w') as f:
            json.dump(analysis_results, f, indent=2)
        
        self.log_investigation_step("File System Analysis", "File system analysis completed")
        return analysis_results
    
    def generate_investigation_report(self):
        """Generate comprehensive investigation report"""
        self.log_investigation_step("Report Generation", "Generating investigation report")
        
        # Collect all analysis results
        network_analysis = self.analyze_network_logs()
        system_analysis = self.analyze_system_logs()
        filesystem_analysis = self.analyze_file_system()
        
        report = {
            'incident_id': self.incident_id,
            'investigation_date': datetime.utcnow().isoformat(),
            'investigator': 'Security Team',
            'findings': {
                'network_analysis': network_analysis,
                'system_analysis': system_analysis,
                'filesystem_analysis': filesystem_analysis
            },
            'investigation_log': self.investigation_log,
            'recommendations': self.generate_recommendations()
        }
        
        with open(f"{self.evidence_dir}/investigation_report.json", 'w') as f:
            json.dump(report, f, indent=2)
        
        self.log_investigation_step("Report Generation", "Investigation report generated")
        return report
    
    def generate_recommendations(self):
        """Generate investigation recommendations"""
        recommendations = [
            "Implement network segmentation to prevent lateral movement",
            "Enhance logging and monitoring capabilities",
            "Conduct regular security awareness training",
            "Implement multi-factor authentication for all systems",
            "Regular vulnerability scanning and patching",
            "Develop and test incident response procedures"
        ]
        
        return recommendations

# Usage
investigator = DataBreachInvestigator("INC-20240101001")
report = investigator.generate_investigation_report()
print(f"Investigation completed. Report saved to evidence directory.")
```

### 2. Ransomware Response Playbook

#### Immediate Response Script
```bash
#!/bin/bash
# ransomware_response.sh

INCIDENT_ID=$1
AFFECTED_SYSTEMS=$2

echo "Starting Ransomware Response for Incident: $INCIDENT_ID"

# Phase 1: Immediate Isolation
echo "Phase 1: Immediate Isolation"
for system in $AFFECTED_SYSTEMS; do
    echo "Isolating system: $system"
    
    # Disconnect from network
    ssh $system "sudo ip link set eth0 down"
    
    # Stop critical services
    ssh $system "sudo systemctl stop nginx"
    ssh $system "sudo systemctl stop mysql"
    ssh $system "sudo systemctl stop apache2"
    
    # Create memory dump for analysis
    ssh $system "sudo dd if=/dev/mem of=/tmp/memory.dump bs=1M count=1024"
    
    echo "System $system isolated"
done

# Phase 2: Evidence Collection
echo "Phase 2: Evidence Collection"
mkdir -p /evidence/$INCIDENT_ID

for system in $AFFECTED_SYSTEMS; do
    echo "Collecting evidence from: $system"
    
    # Collect system information
    ssh $system "sudo ps aux > /tmp/processes.txt"
    ssh $system "sudo netstat -tulnp > /tmp/network_connections.txt"
    ssh $system "sudo ls -la /tmp > /tmp/temp_files.txt"
    
    # Copy evidence to collection point
    scp $system:/tmp/*.txt /evidence/$INCIDENT_ID/${system}_/
    
    # Look for ransom notes
    ssh $system "find / -name '*ransom*' -o -name '*decrypt*' 2>/dev/null > /tmp/ransom_notes.txt"
    scp $system:/tmp/ransom_notes.txt /evidence/$INCIDENT_ID/${system}_ransom_notes.txt
    
    echo "Evidence collected from: $system"
done

# Phase 3: Malware Analysis
echo "Phase 3: Malware Analysis"
python3 scripts/malware_analysis.py --evidence-dir /evidence/$INCIDENT_ID

# Phase 4: Decision Point - Pay or Restore
echo "Phase 4: Recovery Decision"
echo "1. Check backup availability"
echo "2. Assess data criticality"
echo "3. Evaluate ransom payment risks"
echo "4. Make recovery decision"

# Create decision log
cat > /evidence/$INCIDENT_ID/recovery_decision.md << EOF
# Ransomware Recovery Decision

## Backup Assessment
- Last successful backup: $(check_backup_status)
- Backup integrity: $(verify_backup_integrity)
- Recovery time estimate: $(estimate_recovery_time)

## Data Criticality Assessment
- Critical business data affected: $(assess_data_criticality)
- Regulatory implications: $(assess_regulatory_impact)
- Customer impact: $(assess_customer_impact)

## Risk Assessment
- Payment risks: $(assess_payment_risks)
- Non-payment risks: $(assess_non_payment_risks)
- Legal implications: $(assess_legal_implications)

## Decision
[ ] Restore from backups
[ ] Negotiate with attackers
[ ] Accept data loss
[ ] Other: _______________

Decision maker: _______________
Date: $(date)
EOF

echo "Ransomware response initial phases completed"
echo "Next steps: Recovery decision and implementation"
```

## Post-Incident Activities

### 1. Post-Incident Review Framework

#### Lessons Learned Process
```python
# post_incident_review.py
import json
from datetime import datetime, timedelta

class PostIncidentReview:
    def __init__(self, incident_id):
        self.incident_id = incident_id
        self.review_categories = {
            'detection': [
                'How was the incident detected?',
                'How long did it take to detect?',
                'Were detection systems effective?',
                'What could improve detection?'
            ],
            'response': [
                'How quickly was the response initiated?',
                'Were the right people involved?',
                'Were procedures followed?',
                'What could improve response?'
            ],
            'containment': [
                'How effective was containment?',
                'How long did containment take?',
                'Was collateral damage minimized?',
                'What could improve containment?'
            ],
            'recovery': [
                'How quickly was recovery completed?',
                'Were systems fully restored?',
                'Was data integrity maintained?',
                'What could improve recovery?'
            ],
            'communication': [
                'Were stakeholders informed appropriately?',
                'Was communication timely?',
                'Was communication clear?',
                'What could improve communication?'
            ]
        }
    
    def conduct_review(self, incident_data, team_feedback):
        """Conduct post-incident review"""
        review = {
            'incident_id': self.incident_id,
            'review_date': datetime.utcnow().isoformat(),
            'review_team': 'Security Leadership',
            'incident_summary': self.summarize_incident(incident_data),
            'timeline_analysis': self.analyze_timeline(incident_data),
            'performance_assessment': self.assess_performance(incident_data),
            'lessons_learned': self.extract_lessons(incident_data, team_feedback),
            'action_items': self.generate_action_items(incident_data, team_feedback),
            'recommendations': self.generate_recommendations(incident_data, team_feedback)
        }
        
        return review
    
    def summarize_incident(self, incident_data):
        """Summarize incident for review"""
        return {
            'incident_type': incident_data.get('type'),
            'severity': incident_data.get('severity'),
            'duration': self.calculate_duration(incident_data),
            'business_impact': incident_data.get('business_impact'),
            'affected_systems': incident_data.get('affected_systems', []),
            'root_cause': incident_data.get('root_cause', 'Under investigation')
        }
    
    def analyze_timeline(self, incident_data):
        """Analyze incident timeline"""
        timeline = incident_data.get('timeline', [])
        
        # Calculate key metrics
        detection_time = self.find_detection_time(timeline)
        response_time = self.find_response_time(timeline)
        containment_time = self.find_containment_time(timeline)
        recovery_time = self.find_recovery_time(timeline)
        
        return {
            'detection_to_response': self.time_diff(detection_time, response_time),
            'response_to_containment': self.time_diff(response_time, containment_time),
            'containment_to_recovery': self.time_diff(containment_time, recovery_time),
            'total_incident_duration': self.time_diff(detection_time, recovery_time),
            'timeline_milestones': timeline
        }
    
    def assess_performance(self, incident_data):
        """Assess response performance"""
        return {
            'detection_effectiveness': self.rate_detection(incident_data),
            'response_timeliness': self.rate_response(incident_data),
            'containment_effectiveness': self.rate_containment(incident_data),
            'recovery_success': self.rate_recovery(incident_data),
            'communication_quality': self.rate_communication(incident_data),
            'overall_performance': self.calculate_overall_performance(incident_data)
        }
    
    def extract_lessons(self, incident_data, team_feedback):
        """Extract lessons learned"""
        lessons = []
        
        # Extract from incident data
        if incident_data.get('detection_delay', 0) > 60:
            lessons.append({
                'category': 'detection',
                'lesson': 'Detection took too long - need improved monitoring',
                'priority': 'high'
            })
        
        if incident_data.get('containment_issues', []):
            lessons.append({
                'category': 'containment',
                'lesson': 'Containment procedures need refinement',
                'priority': 'medium'
            })
        
        # Extract from team feedback
        for feedback in team_feedback:
            if feedback.get('type') == 'improvement':
                lessons.append({
                    'category': feedback.get('category'),
                    'lesson': feedback.get('lesson'),
                    'priority': feedback.get('priority', 'medium')
                })
        
        return lessons
    
    def generate_action_items(self, incident_data, team_feedback):
        """Generate action items"""
        action_items = []
        
        # Based on lessons learned
        lessons = self.extract_lessons(incident_data, team_feedback)
        
        for lesson in lessons:
            if lesson['category'] == 'detection':
                action_items.append({
                    'action': 'Review and enhance detection capabilities',
                    'owner': 'Security Engineering',
                    'priority': lesson['priority'],
                    'due_date': (datetime.utcnow() + timedelta(days=30)).isoformat(),
                    'status': 'open'
                })
            
            elif lesson['category'] == 'containment':
                action_items.append({
                    'action': 'Update containment procedures',
                    'owner': 'Security Operations',
                    'priority': lesson['priority'],
                    'due_date': (datetime.utcnow() + timedelta(days=15)).isoformat(),
                    'status': 'open'
                })
        
        return action_items
    
    def generate_recommendations(self, incident_data, team_feedback):
        """Generate strategic recommendations"""
        recommendations = [
            'Implement automated incident detection and response',
            'Conduct regular incident response training and drills',
            'Enhance monitoring and logging capabilities',
            'Improve communication protocols and templates',
            'Establish relationships with external security experts',
            'Regularly review and update incident response plans'
        ]
        
        return recommendations
    
    def generate_review_report(self, incident_data, team_feedback):
        """Generate comprehensive review report"""
        review = self.conduct_review(incident_data, team_feedback)
        
        # Save review report
        report_file = f"/evidence/{self.incident_id}/post_incident_review.json"
        with open(report_file, 'w') as f:
            json.dump(review, f, indent=2)
        
        # Generate executive summary
        executive_summary = self.generate_executive_summary(review)
        
        summary_file = f"/evidence/{self.incident_id}/executive_summary.md"
        with open(summary_file, 'w') as f:
            f.write(executive_summary)
        
        return review
    
    def generate_executive_summary(self, review):
        """Generate executive summary"""
        summary = f"""
# Post-Incident Review Executive Summary

## Incident Overview
- **Incident ID**: {review['incident_id']}
- **Type**: {review['incident_summary']['incident_type']}
- **Severity**: {review['incident_summary']['severity']}
- **Duration**: {review['incident_summary']['duration']}
- **Business Impact**: {review['incident_summary']['business_impact']}

## Performance Assessment
- **Detection**: {review['performance_assessment']['detection_effectiveness']}
- **Response**: {review['performance_assessment']['response_timeliness']}
- **Containment**: {review['performance_assessment']['containment_effectiveness']}
- **Recovery**: {review['performance_assessment']['recovery_success']}
- **Overall**: {review['performance_assessment']['overall_performance']}

## Key Findings
{self.format_key_findings(review['lessons_learned'])}

## Action Items
{self.format_action_items(review['action_items'])}

## Strategic Recommendations
{self.format_recommendations(review['recommendations'])}

## Next Review Date
{datetime.utcnow() + timedelta(days=90)}
"""
        return summary

# Usage
reviewer = PostIncidentReview("INC-20240101001")

# Sample incident data and feedback
incident_data = {
    'type': 'Data Breach',
    'severity': 'High',
    'detection_delay': 120,  # minutes
    'containment_issues': ['Initial containment failed'],
    'business_impact': 'Customer data exposed',
    'affected_systems': ['web-server-1', 'database-1'],
    'timeline': [
        {'time': '2024-01-01T10:00:00Z', 'event': 'Incident started'},
        {'time': '2024-01-01T12:00:00Z', 'event': 'Incident detected'},
        {'time': '2024-01-01T12:30:00Z', 'event': 'Response initiated'},
        {'time': '2024-01-01T14:00:00Z', 'event': 'Containment achieved'},
        {'time': '2024-01-01T18:00:00Z', 'event': 'Recovery completed'}
    ]
}

team_feedback = [
    {
        'type': 'improvement',
        'category': 'detection',
        'lesson': 'Need better automated monitoring',
        'priority': 'high'
    }
]

review = reviewer.generate_review_report(incident_data, team_feedback)
print("Post-incident review completed")
```

## Best Practices

### 1. Preparation
- **Regular Training**: Conduct regular IR team training
- **Playbook Development**: Maintain updated playbooks
- **Tool Readiness**: Ensure tools are ready and tested
- **Communication Plans**: Pre-approve communication templates

### 2. Detection
- **Multiple Sources**: Use multiple detection sources
- **Automated Alerting**: Implement automated alerting
- **Baseline Monitoring**: Establish normal baselines
- **Threat Intelligence**: Use threat intelligence feeds

### 3. Response
- **Quick Response**: Respond quickly to incidents
- **Documentation**: Document all actions taken
- **Evidence Preservation**: Preserve forensic evidence
- **Stakeholder Communication**: Communicate with stakeholders

### 4. Recovery
- **Systematic Recovery**: Follow systematic recovery process
- **Validation**: Validate system integrity before restoration
- **Monitoring**: Monitor systems post-recovery
- **Backups**: Maintain secure backup procedures

---

**Implement comprehensive incident response procedures** to effectively handle security incidents and minimize business impact.
