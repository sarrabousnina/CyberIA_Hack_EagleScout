"""MITRE ATT&CK mapping for vulnerabilities."""

from typing import Dict, List, Any


class MITREAttackMapper:
    """
    Map vulnerability types to MITRE ATT&CK tactics and techniques.

    Uses dictionary-based lookup for common vulnerability patterns.
    """

    # MITRE ATT&CK tactic and technique mappings
    ATTACK_MAPPINGS = {
        # SQL Injection
        'sql_injection': {
            'tactic_id': 'TA0001',
            'tactic_name': 'Initial Access',
            'technique_id': 'T1190',
            'technique_name': 'Exploit Public-Facing Application'
        },
        'sql injection': {
            'tactic_id': 'TA0001',
            'tactic_name': 'Initial Access',
            'technique_id': 'T1190',
            'technique_name': 'Exploit Public-Facing Application'
        },
        'sqli': {
            'tactic_id': 'TA0001',
            'tactic_name': 'Initial Access',
            'technique_id': 'T1190',
            'technique_name': 'Exploit Public-Facing Application'
        },

        # Remote Code Execution
        'remote code execution': {
            'tactic_id': 'TA0002',
            'tactic_name': 'Execution',
            'technique_id': 'T1059',
            'technique_name': 'Command and Scripting Interpreter'
        },
        'rce': {
            'tactic_id': 'TA0002',
            'tactic_name': 'Execution',
            'technique_id': 'T1059',
            'technique_name': 'Command and Scripting Interpreter'
        },
        'arbitrary code execution': {
            'tactic_id': 'TA0002',
            'tactic_name': 'Execution',
            'technique_id': 'T1059',
            'technique_name': 'Command and Scripting Interpreter'
        },

        # Privilege Escalation
        'privilege escalation': {
            'tactic_id': 'TA0004',
            'tactic_name': 'Privilege Escalation',
            'technique_id': 'T1068',
            'technique_name': 'Exploitation for Privilege Escalation'
        },
        'escalation of privilege': {
            'tactic_id': 'TA0004',
            'tactic_name': 'Privilege Escalation',
            'technique_id': 'T1068',
            'technique_name': 'Exploitation for Privilege Escalation'
        },
        'eop': {
            'tactic_id': 'TA0004',
            'tactic_name': 'Privilege Escalation',
            'technique_id': 'T1068',
            'technique_name': 'Exploitation for Privilege Escalation'
        },

        # Data Exfiltration
        'data exfiltration': {
            'tactic_id': 'TA0010',
            'tactic_name': 'Exfiltration',
            'technique_id': 'T1041',
            'technique_name': 'Exfiltration Over C2 Channel'
        },
        'information disclosure': {
            'tactic_id': 'TA0010',
            'tactic_name': 'Exfiltration',
            'technique_id': 'T1041',
            'technique_name': 'Exfiltration Over C2 Channel'
        },

        # Denial of Service
        'denial of service': {
            'tactic_id': 'TA0040',
            'tactic_name': 'Impact',
            'technique_id': 'T1498',
            'technique_name': 'Network Denial of Service'
        },
        'dos': {
            'tactic_id': 'TA0040',
            'tactic_name': 'Impact',
            'technique_id': 'T1498',
            'technique_name': 'Network Denial of Service'
        },
        'ddos': {
            'tactic_id': 'TA0040',
            'tactic_name': 'Impact',
            'technique_id': 'T1498',
            'technique_name': 'Network Denial of Service'
        },

        # Cross-Site Scripting
        'cross-site scripting': {
            'tactic_id': 'TA0001',
            'tactic_name': 'Initial Access',
            'technique_id': 'T1190',
            'technique_name': 'Exploit Public-Facing Application'
        },
        'xss': {
            'tactic_id': 'TA0001',
            'tactic_name': 'Initial Access',
            'technique_id': 'T1190',
            'technique_name': 'Exploit Public-Facing Application'
        },

        # Buffer Overflow
        'buffer overflow': {
            'tactic_id': 'TA0002',
            'tactic_name': 'Execution',
            'technique_id': 'T1059',
            'technique_name': 'Command and Scripting Interpreter'
        },
        'memory corruption': {
            'tactic_id': 'TA0002',
            'tactic_name': 'Execution',
            'technique_id': 'T1059',
            'technique_name': 'Command and Scripting Interpreter'
        },

        # Authentication Bypass
        'authentication bypass': {
            'tactic_id': 'TA0006',
            'tactic_name': 'Credential Access',
            'technique_id': 'T1078',
            'technique_name': 'Valid Accounts'
        },
        'auth bypass': {
            'tactic_id': 'TA0006',
            'tactic_name': 'Credential Access',
            'technique_id': 'T1078',
            'technique_name': 'Valid Accounts'
        },

        # Path Traversal
        'path traversal': {
            'tactic_id': 'TA0001',
            'tactic_name': 'Initial Access',
            'technique_id': 'T1190',
            'technique_name': 'Exploit Public-Facing Application'
        },
        'directory traversal': {
            'tactic_id': 'TA0001',
            'tactic_name': 'Initial Access',
            'technique_id': 'T1190',
            'technique_name': 'Exploit Public-Facing Application'
        },

        # XML External Entity
        'xml external entity': {
            'tactic_id': 'TA0001',
            'tactic_name': 'Initial Access',
            'technique_id': 'T1190',
            'technique_name': 'Exploit Public-Facing Application'
        },
        'xxe': {
            'tactic_id': 'TA0001',
            'tactic_name': 'Initial Access',
            'technique_id': 'T1190',
            'technique_name': 'Exploit Public-Facing Application'
        },

        # Server-Side Request Forgery
        'server-side request forgery': {
            'tactic_id': 'TA0001',
            'tactic_name': 'Initial Access',
            'technique_id': 'T1190',
            'technique_name': 'Exploit Public-Facing Application'
        },
        'ssrf': {
            'tactic_id': 'TA0001',
            'tactic_name': 'Initial Access',
            'technique_id': 'T1190',
            'technique_name': 'Exploit Public-Facing Application'
        }
    }

    @classmethod
    def map_vulnerability_to_attack(cls, vulnerability_text: str) -> List[Dict[str, str]]:
        """
        Map vulnerability description to MITRE ATT&CK tactics/techniques.

        Args:
            vulnerability_text: Description of vulnerability

        Returns:
            List of mappings with tactic_id, tactic_name, technique_id, technique_name
        """
        mappings = []
        text_lower = vulnerability_text.lower()

        # Check for known vulnerability patterns
        for vuln_type, attack_data in cls.ATTACK_MAPPINGS.items():
            if vuln_type in text_lower:
                mapping = {
                    'tactic_id': attack_data['tactic_id'],
                    'tactic_name': attack_data['tactic_name'],
                    'technique_id': attack_data['technique_id'],
                    'technique_name': attack_data['technique_name'],
                    'vulnerability_type': vuln_type
                }
                mappings.append(mapping)

        # Remove duplicates while preserving order
        seen = set()
        unique_mappings = []
        for mapping in mappings:
            key = (mapping['tactic_id'], mapping['technique_id'])
            if key not in seen:
                seen.add(key)
                unique_mappings.append(mapping)

        return unique_mappings

    @classmethod
    def map_cve(cls, cve: Dict[str, Any]) -> List[Dict[str, str]]:
        """
        Map CVE to MITRE ATT&CK tactics/techniques.

        Args:
            cve: CVE dictionary

        Returns:
            List of MITRE ATT&CK mappings
        """
        # Extract vulnerability description
        description = cve.get('description', '')
        summary = cve.get('summary', {})

        # Combine description and summary
        summary_desc = summary.get('brief_description', '') if isinstance(summary, dict) else str(summary)

        combined_text = f"{description} {summary_desc}".lower()

        # Map to MITRE ATT&CK
        return cls.map_vulnerability_to_attack(combined_text)

    @classmethod
    def format_mitre_tags(cls, mappings: List[Dict[str, str]]) -> List[str]:
        """
        Format MITRE ATT&CK mappings into tags.

        Args:
            mappings: List of MITRE ATT&CK mappings

        Returns:
            List of formatted tags (e.g., "TA0001/T1190")
        """
        tags = []

        for mapping in mappings:
            tag = f"{mapping['tactic_id']}/{mapping['technique_id']}"
            tags.append(tag)

        return tags


if __name__ == "__main__":
    # Test the mapper
    test_cves = [
        {
            'cve_id': 'CVE-2023-1234',
            'description': 'SQL injection vulnerability in web application',
            'summary': {'brief_description': 'SQLi allows authentication bypass'}
        },
        {
            'cve_id': 'CVE-2023-5678',
            'description': 'Remote code execution in nginx server',
            'summary': {'brief_description': 'RCE via memory corruption'}
        },
        {
            'cve_id': 'CVE-2023-9012',
            'description': 'Privilege escalation in PostgreSQL database',
            'summary': {'brief_description': 'EOP vulnerability'}
        }
    ]

    mapper = MITREAttackMapper()

    for cve in test_cves:
        mappings = mapper.map_cve(cve)
        tags = mapper.format_mitre_tags(mappings)

        print(f"\n{cve['cve_id']}:")
        print(f"  Mappings: {len(mappings)}")
        for mapping in mappings:
            print(f"    - {mapping['tactic_name']} ({mapping['tactic_id']}) / {mapping['technique_name']} ({mapping['technique_id']})")
        print(f"  Tags: {tags}")
