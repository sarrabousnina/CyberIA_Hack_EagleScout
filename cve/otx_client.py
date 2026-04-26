"""OTX (AlienVault Open Threat Exchange) API client for CVE enrichment."""

import os
from typing import Dict, Any, Optional
import requests
from dotenv import load_dotenv

load_dotenv()


class OTXClient:
    """Client for enriching CVEs with OTX threat intelligence."""

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize OTX client.

        Args:
            api_key: OTX API key (optional, from env if not provided)
        """
        self.api_key = api_key or os.getenv('OTX_API_KEY')
        self.base_url = "https://otx.alienvault.com/api/v1"

        if not self.api_key:
            print("Warning: No OTX API key found. Enrichment will be limited.")

    def enrich_cve(self, cve_id: str) -> Dict[str, Any]:
        """
        Enrich a single CVE with OTX data.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2023-1234")

        Returns:
            Dictionary with enrichment data
        """
        enrichment = {
            'pulse_count': 0,
            'malware_families': [],
            'active_exploitation': False,
            'first_seen': None,
            'last_seen': None
        }

        if not self.api_key:
            return enrichment

        try:
            # Get pulses associated with this CVE
            pulses = self._get_cve_pulses(cve_id)
            enrichment['pulse_count'] = len(pulses)

            # Extract malware families from pulses
            malware_families = set()
            for pulse in pulses:
                if 'malware_families' in pulse:
                    for mal in pulse['malware_families']:
                        malware_families.add(mal.get('name', 'Unknown'))

            enrichment['malware_families'] = list(malware_families)

            # Check for active exploitation indicators
            # High pulse count or recent activity suggests active exploitation
            if len(pulses) >= 3:
                enrichment['active_exploitation'] = True

            # Get date range
            if pulses:
                timestamps = [p.get('created', None) for p in pulses if p.get('created')]
                if timestamps:
                    enrichment['first_seen'] = min(timestamps)
                    enrichment['last_seen'] = max(timestamps)

        except Exception as e:
            print(f"Error enriching {cve_id} with OTX: {e}")

        return enrichment

    def _get_cve_pulses(self, cve_id: str) -> list:
        """
        Get pulses (threat reports) associated with a CVE.

        Args:
            cve_id: CVE identifier

        Returns:
            List of pulse dictionaries
        """
        pulses = []

        try:
            # Search for pulses by CVE ID
            url = f"{self.base_url}/search/pulses"
            params = {
                'q': cve_id,
                'limit': 20
            }
            headers = {
                'X-OTX-API-KEY': self.api_key
            }

            response = requests.get(url, params=params, headers=headers, timeout=10)
            response.raise_for_status()

            data = response.json()

            if 'results' in data:
                pulses = data['results']

        except requests.exceptions.RequestException as e:
            print(f"Error fetching pulses for {cve_id}: {e}")

        return pulses

    def batch_enrich_cves(self, cve_list: list) -> Dict[str, Dict[str, Any]]:
        """
        Enrich multiple CVEs in batch.

        Args:
            cve_list: List of CVE dictionaries with 'cve_id' field

        Returns:
            Dictionary mapping CVE ID to enrichment data
        """
        enrichment_map = {}

        for cve in cve_list:
            cve_id = cve.get('cve_id')
            if cve_id:
                enrichment_map[cve_id] = self.enrich_cve(cve_id)

        return enrichment_map


if __name__ == "__main__":
    # Test the client
    client = OTXClient()

    # Test enrichment for a known CVE
    test_cve = "CVE-2023-23397"  # Microsoft Outlook vulnerability
    enrichment = client.enrich_cve(test_cve)

    print(f"\nEnrichment for {test_cve}:")
    print(f"  Pulse count: {enrichment['pulse_count']}")
    print(f"  Malware families: {enrichment['malware_families']}")
    print(f"  Active exploitation: {enrichment['active_exploitation']}")
