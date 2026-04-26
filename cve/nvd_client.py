"""NVD (National Vulnerability Database) API client for CVE fetching."""

import os
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import nvdlib
from dotenv import load_dotenv

load_dotenv()


class NVDClient:
    """Client for fetching CVEs from NVD API."""

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize NVD client.

        Args:
            api_key: NVD API key (optional, from env if not provided)
        """
        self.api_key = api_key or os.getenv('NVD_API_KEY')
        if not self.api_key:
            print("Warning: No NVD API key found. Rate limits will apply.")

    def fetch_cves_delta(
        self,
        start_date: datetime,
        end_date: Optional[datetime] = None,
        max_results: int = 2000
    ) -> List[Dict[str, Any]]:
        """
        Fetch CVEs published within a date range (delta fetch).

        Args:
            start_date: Start date for CVE fetch
            end_date: End date (defaults to now)
            max_results: Maximum total results to fetch

        Returns:
            List of CVE dictionaries with key information
        """
        if end_date is None:
            end_date = datetime.now()

        print(f"Fetching CVEs from {start_date.date()} to {end_date.date()}")

        cves = []
        try:
            # Use nvdlib to search CVEs by date
            # Note: nvdlib handles pagination internally
            # Format dates as 'YYYY-MM-DD HH:MM'
            start_date_str = start_date.strftime('%Y-%m-%d %H:%M')
            end_date_str = end_date.strftime('%Y-%m-%d %H:%M')

            results = nvdlib.searchCVE(
                pubStartDate=start_date_str,
                pubEndDate=end_date_str,
                key=self.api_key,
                limit=max_results
            )

            for cve in results:
                cve_data = self._extract_cve_data(cve)
                if cve_data:
                    cves.append(cve_data)

            print(f"Fetched {len(cves)} CVEs from NVD")

        except Exception as e:
            print(f"Error fetching CVEs from NVD: {e}")

        return cves

    def _extract_cve_data(self, cve: Any) -> Optional[Dict[str, Any]]:
        """
        Extract relevant data from a CVE object.

        Args:
            cve: nvdlib CVE object

        Returns:
            Dictionary with extracted CVE data
        """
        try:
            # Basic CVE info
            cve_id = cve.id
            description = ""
            if cve.descriptions and len(cve.descriptions) > 0:
                description = cve.descriptions[0].value

            # CVSS scores - use direct attributes from nvdlib
            cvss_v3_score = getattr(cve, 'v31score', None)
            cvss_v3_severity = getattr(cve, 'v31severity', None)

            # Affected products - extract from configurations if available
            affected_products = []
            # For now, create basic product identifiers from CVE ID
            # (nvdlib doesn't easily expose CPE data in the current version)
            if 'nginx' in description.lower():
                affected_products.append('nginx')
            if 'apache' in description.lower():
                affected_products.append('apache')
            if 'postgresql' in description.lower() or 'postgres' in description.lower():
                affected_products.append('postgresql')

            # Published date
            published_date = getattr(cve, 'published', None)

            # Modified date
            modified_date = getattr(cve, 'lastModified', None)

            return {
                'cve_id': cve_id,
                'description': description,
                'cvss_v3_score': cvss_v3_score,
                'cvss_v3_severity': cvss_v3_severity,
                'cvss_v2_score': None,
                'affected_products': affected_products[:5],  # Limit to first 5
                'published_date': published_date if isinstance(published_date, str) else (published_date.isoformat() if published_date else None),
                'modified_date': modified_date if isinstance(modified_date, str) else (modified_date.isoformat() if modified_date else None)
            }

        except Exception as e:
            print(f"Error extracting data for CVE {cve.id if hasattr(cve, 'id') else 'unknown'}: {e}")
            return None

    def fetch_recent_cves(self, days_back: int = 7, max_results: int = 2000) -> List[Dict[str, Any]]:
        """
        Fetch CVEs from the last N days.

        Args:
            days_back: Number of days to look back
            max_results: Maximum results to fetch

        Returns:
            List of CVE dictionaries
        """
        start_date = datetime.now() - timedelta(days=days_back)
        return self.fetch_cves_delta(start_date, max_results=max_results)

    def fetch_cves_for_tech_stack(
        self,
        tech_components: List[Dict[str, Any]],
        max_results_per_tech: int = 50
    ) -> List[Dict[str, Any]]:
        """
        Fetch CVEs by keyword search for each technology in the stack.

        This is MORE effective than date-based fetching because:
        - Finds CVEs for specific products regardless of age
        - No 90-day window limitation
        - More relevant results

        Args:
            tech_components: List of component dicts with 'name' and 'type'
            max_results_per_tech: Max CVEs to fetch per technology

        Returns:
            List of CVE dictionaries with key information
        """
        all_cves = []
        seen_cve_ids = set()

        # Import product mapping
        import sys
        sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from PRODUCT_MAPPING import extract_product_name

        # Extract unique base product names
        products_searched = set()

        for component in tech_components:
            comp_name = component.get('name', '')
            comp_type = component.get('type', '')

            # Use smart product extraction
            product = extract_product_name(comp_name, comp_type)

            # Skip if product is too generic
            if not product:
                print(f"⚠️ Skipping generic component: {comp_name}")
                continue

            # Skip if we already searched this product
            if product in products_searched:
                continue

            print(f"Searching NVD for: {product}")

            try:
                # Use nvdlib keyword search
                results = nvdlib.searchCVE(
                    keywordSearch=product,
                    key=self.api_key,
                    limit=max_results_per_tech
                )

                # Extract and deduplicate CVEs
                for cve in results:
                    cve_id = cve.id

                    # Skip duplicates
                    if cve_id in seen_cve_ids:
                        continue

                    cve_data = self._extract_cve_data(cve)
                    if cve_data:
                        all_cves.append(cve_data)
                        seen_cve_ids.add(cve_id)

                products_searched.add(product)
                print(f"  Found {len(results)} CVEs for '{product}'")

            except Exception as e:
                print(f"Error searching for '{product}': {e}")

        print(f"Total CVEs fetched (deduplicated): {len(all_cves)}")
        return all_cves


if __name__ == "__main__":
    # Test the client
    client = NVDClient()

    # Fetch recent CVEs from last 30 days
    cves = client.fetch_recent_cves(days_back=30)

    print(f"\nRecent CVEs found: {len(cves)}")
    for cve in cves[:3]:  # Show first 3
        print(f"\n{cve['cve_id']}:")
        print(f"  Score: {cve['cvss_v3_score'] or cve['cvss_v2_score']}")
        print(f"  Description: {cve['description'][:100]}...")
