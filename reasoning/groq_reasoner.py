"""Groq-based security reasoning client (cloud-based alternative to Ollama)."""

import os
from typing import Dict, Any
from groq import Groq
from dotenv import load_dotenv

load_dotenv()


class GroqSecurityReasoner:
    """
    Cloud-based security reasoning using Groq API.

    Takes CVE + user architecture and produces:
    - Risk score (1-10)
    - Base severity (CVSS-based)
    - Context multiplier (architecture-aware)
    - Reasoning trace
    - Confidence level
    - Recommended action
    """

    def __init__(self, model_name: str = "llama-3.3-70b-versatile"):
        """
        Initialize Groq security reasoner.

        Args:
            model_name: Groq model name
        """
        self.model_name = model_name
        api_key = os.getenv('GROQ_API_KEY')

        if not api_key:
            raise ValueError("GROQ_API_KEY not found in environment variables")

        self.client = Groq(api_key=api_key)

    def _build_prompt(
        self,
        cve: Dict[str, Any],
        infrastructure: Dict[str, Any]
    ) -> str:
        """
        Build prompt for Groq reasoning.

        Args:
            cve: CVE dictionary
            infrastructure: User infrastructure dictionary

        Returns:
            Prompt string
        """
        prompt = f"""You are a cybersecurity expert analyzing vulnerability risk for a specific infrastructure.

CVE Information:
- ID: {cve.get('cve_id')}
- Description: {cve.get('description', 'N/A')}
- CVSS v3 Score: {cve.get('cvss_v3_score', 'N/A')}
- CVSS v3 Severity: {cve.get('cvss_v3_severity', 'N/A')}
- Affected Products: {', '.join(cve.get('affected_products', [])[:3])}
- Active Exploitation (OTX): {cve.get('otx_active_exploitation', False)}

Infrastructure Context:
Sector: {infrastructure.get('sector', 'general')}

Components:
{self._format_components(infrastructure.get('components', []))}

Connections:
{self._format_connections(infrastructure.get('connections', []))}

Exposed Components: {infrastructure.get('exposed_components', [])}
Critical Components: {infrastructure.get('critical_components', [])}

Analyze this CVE in the context of this specific infrastructure and provide:

1. BASE SEVERITY (1-10): Based purely on CVSS score
2. CONTEXT MULTIPLIER (0.5-2.0): Based on:
   - Whether affected component is exposed
   - Network path from exposed to critical assets
   - Active exploitation indicators
   - Sector-specific risk
3. RISK SCORE (1-10): BASE SEVERITY × CONTEXT MULTIPLIER (clamp to 1-10)
4. REASONING TRACE: Explain your analysis in 2-3 sentences
5. CONFIDENCE (1-5): How confident in this assessment
6. RECOMMENDED ACTION: One specific action (e.g., "Patch immediately", "Isolate from network", "Monitor for exploitation")

Return response as JSON only:
{{
    "base_severity": <1-10>,
    "context_multiplier": <0.5-2.0>,
    "risk_score": <1-10>,
    "reasoning_trace": "<explanation>",
    "confidence": <1-5>,
    "recommended_action": "<action>"
}}"""

        return prompt

    def _format_components(self, components: list) -> str:
        """Format components for prompt."""
        return '\n'.join([
            f"- {c['name']} ({c['type']} v{c['version']}) "
            f"{'[EXPOSED]' if c.get('exposed') else ''} "
            f"{'[CRITICAL]' if c.get('critical') else ''}"
            for c in components
        ])

    def _format_connections(self, connections: list) -> str:
        """Format connections for prompt."""
        return '\n'.join([
            f"- {conn['from']} → {conn['to']} ({conn['protocol']})"
            for conn in connections
        ])

    def reason_about_cve(
        self,
        cve: Dict[str, Any],
        infrastructure: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Perform security reasoning on a CVE.

        Args:
            cve: CVE dictionary
            infrastructure: User infrastructure dictionary

        Returns:
            Dictionary with reasoning results
        """
        prompt = self._build_prompt(cve, infrastructure)

        try:
            # Call Groq
            response = self.client.chat.completions.create(
                model=self.model_name,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3,
                max_tokens=500,
                response_format={"type": "json_object"}
            )

            # Parse response
            response_text = response.choices[0].message.content.strip()

            # Parse JSON
            import json
            reasoning_result = json.loads(response_text)

            # Ensure all required fields are present
            result = {
                'base_severity': reasoning_result.get('base_severity', 5),
                'context_multiplier': reasoning_result.get('context_multiplier', 1.0),
                'risk_score': reasoning_result.get('risk_score', 5),
                'reasoning_trace': reasoning_result.get('reasoning_trace', 'Analysis not available'),
                'confidence': reasoning_result.get('confidence', 3),
                'recommended_action': reasoning_result.get('recommended_action', 'Review and patch')
            }

        except Exception as e:
            print(f"Error performing reasoning for {cve.get('cve_id')}: {e}")
            # Fallback to CVSS-based scoring
            base_severity = self._cvss_to_base_severity(cve.get('cvss_v3_score'))
            result = {
                'base_severity': base_severity,
                'context_multiplier': 1.0,
                'risk_score': base_severity,
                'reasoning_trace': 'Analysis unavailable - using CVSS score only',
                'confidence': 1,
                'recommended_action': 'Review vulnerability details'
            }

        return result

    def _cvss_to_base_severity(self, cvss_score: float) -> int:
        """
        Convert CVSS score to 1-10 scale.

        Args:
            cvss_score: CVSS score (0-10)

        Returns:
            Base severity (1-10)
        """
        if cvss_score is None:
            return 5

        # CVSS is already 0-10, just clamp and convert to int
        return max(1, min(10, int(cvss_score)))

    def batch_reason(
        self,
        cves: list,
        infrastructure: Dict[str, Any]
    ) -> Dict[str, Dict[str, Any]]:
        """
        Perform reasoning on multiple CVEs.

        Args:
            cves: List of CVE dictionaries
            infrastructure: User infrastructure dictionary

        Returns:
            Dictionary mapping CVE ID to reasoning results
        """
        results = {}

        print(f"Performing security reasoning on {len(cves)} CVEs...")

        for i, cve in enumerate(cves):
            if i % 5 == 0:
                print(f"  Reasoning about CVE {i+1}/{len(cves)}...")

            cve_id = cve.get('cve_id')
            if cve_id:
                results[cve_id] = self.reason_about_cve(cve, infrastructure)

        return results


if __name__ == "__main__":
    # Test the reasoner
    from dotenv import load_dotenv
    load_dotenv()

    reasoner = GroqSecurityReasoner()

    # Sample infrastructure
    sample_infrastructure = {
        'sector': 'banking',
        'components': [
            {'name': 'nginx-frontend', 'type': 'web_server', 'version': '1.18.0', 'exposed': True, 'critical': False},
            {'name': 'postgres-db', 'type': 'database', 'version': '12.4', 'exposed': False, 'critical': True}
        ],
        'connections': [
            {'from': 'nginx-frontend', 'to': 'postgres-db', 'protocol': 'HTTP'}
        ],
        'exposed_components': ['nginx-frontend'],
        'critical_components': ['postgres-db']
    }

    # Sample CVE
    sample_cve = {
        'cve_id': 'CVE-2021-23017',
        'description': 'nginx before 1.18.0 has a memory corruption vulnerability',
        'cvss_v3_score': 7.5,
        'cvss_v3_severity': 'HIGH',
        'affected_products': ['nginx:1.18.0'],
        'otx_active_exploitation': False
    }

    # Perform reasoning
    result = reasoner.reason_about_cve(sample_cve, sample_infrastructure)

    print(f"\nReasoning result for {sample_cve['cve_id']}:")
    import json
    print(json.dumps(result, indent=2))
