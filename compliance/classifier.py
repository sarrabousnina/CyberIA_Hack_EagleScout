"""Compliance framework classifier based on sector."""

from typing import Dict, List, Any
from enum import Enum


class ComplianceFramework(str, Enum):
    """Compliance frameworks."""
    PCI_DSS = "PCI-DSS"
    BASEL_CYBER = "Basel III Cyber"
    HIPAA = "HIPAA"
    IEC_62443 = "IEC 62443"
    NIS2 = "NIS2"
    ISO_27001 = "ISO 27001"
    GDPR = "GDPR"


class ComplianceClassifier:
    """
    Classify vulnerabilities by compliance framework based on sector.

    Uses rule-based matching to tag vulnerabilities with relevant frameworks.
    """

    # Sector to compliance frameworks mapping
    SECTOR_FRAMEWORKS = {
        'banking': [
            ComplianceFramework.PCI_DSS,
            ComplianceFramework.BASEL_CYBER,
            ComplianceFramework.ISO_27001
        ],
        'healthcare': [
            ComplianceFramework.HIPAA,
            ComplianceFramework.IEC_62443,
            ComplianceFramework.ISO_27001
        ],
        'telecom': [
            ComplianceFramework.NIS2,
            ComplianceFramework.ISO_27001,
            ComplianceFramework.GDPR
        ],
        'general': [
            ComplianceFramework.ISO_27001
        ]
    }

    # Vulnerability type to compliance requirements mapping
    VULNERABILITY_COMPLIANCE_MAPPING = {
        # PCI-DSS relevant
        'sql_injection': [ComplianceFramework.PCI_DSS],
        'authentication bypass': [ComplianceFramework.PCI_DSS],
        'data exfiltration': [ComplianceFramework.PCI_DSS, ComplianceFramework.HIPAA],
        'information disclosure': [ComplianceFramework.PCI_DSS, ComplianceFramework.HIPAA],

        # HIPAA relevant
        'remote code execution': [ComplianceFramework.HIPAA, ComplianceFramework.IEC_62443],
        'denial of service': [ComplianceFramework.HIPAA, ComplianceFramework.NIS2],

        # IEC 62443 relevant (industrial/healthcare)
        'buffer overflow': [ComplianceFramework.IEC_62443],
        'memory corruption': [ComplianceFramework.IEC_62443],
        'privilege escalation': [ComplianceFramework.IEC_62443],

        # NIS2 relevant (telecom)
        'cross-site scripting': [ComplianceFramework.NIS2, ComplianceFramework.PCI_DSS],
        'ddos': [ComplianceFramework.NIS2],

        # ISO 27001 relevant (general)
        'path traversal': [ComplianceFramework.ISO_27001],
        'xxe': [ComplianceFramework.ISO_27001],
        'ssrf': [ComplianceFramework.ISO_27001]
    }

    # Risk score to compliance violation risk mapping
    RISK_TO_VIOLATION = {
        'critical': (9.0, 10.0),  # High violation risk
        'high': (7.0, 9.0),       # Moderate-high violation risk
        'medium': (4.0, 7.0),     # Moderate violation risk
        'low': (1.0, 4.0)         # Low violation risk
    }

    def __init__(self, sector: str = 'general'):
        """
        Initialize compliance classifier for a sector.

        Args:
            sector: Industry sector (banking, healthcare, telecom, general)
        """
        self.sector = sector.lower()
        self.applicable_frameworks = self.SECTOR_FRAMEWORKS.get(
            self.sector,
            self.SECTOR_FRAMEWORKS['general']
        )

    def classify_vulnerability(self, cve: Dict[str, Any]) -> Dict[str, Any]:
        """
        Classify a CVE by applicable compliance frameworks.

        Args:
            cve: CVE dictionary with reasoning results

        Returns:
            Dictionary with compliance classification
        """
        # Get risk score
        reasoning = cve.get('reasoning', {})
        risk_score = reasoning.get('risk_score', 0)

        # Determine violation risk level
        violation_risk = self._determine_violation_risk(risk_score)

        # Identify relevant frameworks based on vulnerability type
        vuln_frameworks = self._get_vulnerability_frameworks(cve)

        # Combine with sector frameworks
        relevant_frameworks = list(set(
            self.applicable_frameworks + vuln_frameworks
        ))

        # Check if this is a compliance violation
        is_violation = self._is_compliance_violation(
            risk_score,
            cve.get('otx_active_exploitation', False),
            reasoning.get('confidence', 0)
        )

        return {
            'sector': self.sector,
            'applicable_frameworks': [f.value for f in relevant_frameworks],
            'violation_risk': violation_risk,
            'is_compliance_violation': is_violation,
            'justification': self._generate_justification(
                risk_score,
                is_violation,
                relevant_frameworks
            )
        }

    def _determine_violation_risk(self, risk_score: float) -> str:
        """
        Determine violation risk level from risk score.

        Args:
            risk_score: Risk score (1-10)

        Returns:
            Risk level string
        """
        if risk_score >= 9.0:
            return 'critical'
        elif risk_score >= 7.0:
            return 'high'
        elif risk_score >= 4.0:
            return 'medium'
        else:
            return 'low'

    def _get_vulnerability_frameworks(self, cve: Dict[str, Any]) -> List[ComplianceFramework]:
        """
        Get compliance frameworks relevant to vulnerability type.

        Args:
            cve: CVE dictionary

        Returns:
            List of relevant compliance frameworks
        """
        frameworks = []

        # Check description and summary for vulnerability types
        description = cve.get('description', '').lower()
        summary = cve.get('summary', {})
        summary_desc = summary.get('brief_description', '').lower() if isinstance(summary, dict) else ''

        combined_text = f"{description} {summary_desc}"

        # Check for known vulnerability types
        for vuln_type, vuln_frameworks in self.VULNERABILITY_COMPLIANCE_MAPPING.items():
            if vuln_type in combined_text:
                frameworks.extend(vuln_frameworks)

        return frameworks

    def _is_compliance_violation(
        self,
        risk_score: float,
        active_exploitation: bool,
        confidence: int
    ) -> bool:
        """
        Determine if this CVE constitutes a compliance violation.

        Args:
            risk_score: Risk score (1-10)
            active_exploitation: Whether vulnerability is actively exploited
            confidence: Confidence in assessment (1-5)

        Returns:
            True if likely a compliance violation
        """
        # High risk score + active exploitation = violation
        if risk_score >= 7.0 and active_exploitation:
            return True

        # Very high risk score = violation
        if risk_score >= 9.0:
            return True

        # High risk + high confidence = likely violation
        if risk_score >= 7.0 and confidence >= 4:
            return True

        return False

    def _generate_justification(
        self,
        risk_score: float,
        is_violation: bool,
        frameworks: List[ComplianceFramework]
    ) -> str:
        """
        Generate justification for compliance classification.

        Args:
            risk_score: Risk score
            is_violation: Whether this is a violation
            frameworks: Relevant compliance frameworks

        Returns:
            Justification string
        """
        framework_names = [f.value for f in frameworks]

        if is_violation:
            return (
                f"Risk score {risk_score:.1f}/10 indicates potential violation of "
                f"{', '.join(framework_names)}. Immediate remediation required."
            )
        else:
            return (
                f"Risk score {risk_score:.1f}/10. Review against "
                f"{', '.join(framework_names)} requirements."
            )

    def batch_classify(self, cves: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """
        Classify multiple CVEs.

        Args:
            cves: List of CVE dictionaries

        Returns:
            Dictionary mapping CVE ID to compliance classification
        """
        classifications = {}

        for cve in cves:
            cve_id = cve.get('cve_id')
            if cve_id:
                classifications[cve_id] = self.classify_vulnerability(cve)

        return classifications

    def get_sector_summary(self) -> Dict[str, Any]:
        """
        Get summary of compliance requirements for sector.

        Returns:
            Dictionary with sector compliance information
        """
        return {
            'sector': self.sector,
            'applicable_frameworks': [f.value for f in self.applicable_frameworks],
            'framework_count': len(self.applicable_frameworks)
        }


if __name__ == "__main__":
    # Test the classifier
    classifier = ComplianceClassifier(sector='banking')

    # Sample CVEs
    sample_cves = [
        {
            'cve_id': 'CVE-2023-1234',
            'description': 'SQL injection vulnerability in payment processing',
            'reasoning': {'risk_score': 9.5, 'confidence': 5},
            'otx_active_exploitation': True
        },
        {
            'cve_id': 'CVE-2023-5678',
            'description': 'Denial of service in web server',
            'reasoning': {'risk_score': 5.0, 'confidence': 3},
            'otx_active_exploitation': False
        },
        {
            'cve_id': 'CVE-2023-9012',
            'description': 'Information disclosure in database',
            'reasoning': {'risk_score': 7.5, 'confidence': 4},
            'otx_active_exploitation': False
        }
    ]

    # Classify
    for cve in sample_cves:
        classification = classifier.classify_vulnerability(cve)
        print(f"\n{cve['cve_id']}:")
        print(f"  Frameworks: {', '.join(classification['applicable_frameworks'])}")
        print(f"  Violation Risk: {classification['violation_risk']}")
        print(f"  Is Violation: {classification['is_compliance_violation']}")
        print(f"  Justification: {classification['justification']}")

    # Sector summary
    print(f"\nSector Summary:")
    print(classifier.get_sector_summary())
