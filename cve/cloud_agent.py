"""Background agent that fetches CVEs, enriches them, and writes to shared state."""

import json
import os
import threading
import time
from datetime import datetime
from typing import Dict, List, Any
from pathlib import Path

from dotenv import load_dotenv
from groq import Groq

from .nvd_client import NVDClient
from .otx_client import OTXClient

load_dotenv()


class CloudCVEAgent:
    """
    Background agent that continuously fetches and processes CVEs.

    Runs in a separate thread, firing every 60 seconds to:
    1. Fetch new CVEs from NVD (delta from last check)
    2. Enrich with OTX threat intelligence
    3. Summarize with Groq
    4. Write to shared_state.json (local bridge file)
    """

    def __init__(
        self,
        shared_state_path: str = "shared_state.json",
        check_interval: int = 60,
        start_date: str = None
    ):
        """
        Initialize cloud CVE agent.

        Args:
            shared_state_path: Path to shared state JSON file
            check_interval: Seconds between checks (default: 60)
            start_date: Start date for CVE fetching (YYYY-MM-DD). Defaults to 30 days ago.
        """
        self.shared_state_path = Path(shared_state_path)
        self.check_interval = check_interval

        # Default to 30 days ago if no start_date provided
        if start_date:
            self.start_date = datetime.fromisoformat(start_date)
        else:
            from datetime import timedelta
            self.start_date = datetime.now() - timedelta(days=30)

        # Initialize clients
        self.nvd_client = NVDClient()
        self.otx_client = OTXClient()
        self.groq_client = Groq(api_key=os.getenv('GROQ_API_KEY'))

        # State management
        self.last_fetch_time = None
        self.running = False
        self.thread = None

        # Initialize shared state file
        self._init_shared_state()

    def _init_shared_state(self):
        """Initialize shared state file if it doesn't exist."""
        if not self.shared_state_path.exists():
            initial_state = {
                'last_updated': None,
                'cves': [],
                'metadata': {
                    'total_cves': 0,
                    'last_fetch_count': 0
                }
            }
            self._write_shared_state(initial_state)

    def _read_shared_state(self) -> Dict[str, Any]:
        """Read shared state from file."""
        try:
            with open(self.shared_state_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error reading shared state: {e}")
            return {'cves': [], 'last_updated': None}

    def _write_shared_state(self, state: Dict[str, Any]):
        """Write shared state to file."""
        try:
            with open(self.shared_state_path, 'w') as f:
                json.dump(state, f, indent=2)
        except Exception as e:
            print(f"Error writing shared state: {e}")

    def _summarize_cve_with_groq(self, cve: Dict[str, Any]) -> str:
        """
        Use Groq to create a compact summary of CVE data.

        Args:
            cve: Raw CVE dictionary from NVD

        Returns:
            Compact JSON string summary
        """
        prompt = f"""Summarize this CVE data into a compact JSON format. Include:
- cve_id
- brief_description (max 50 words)
- affected_technologies (list)
- attack_vector (e.g., "network", "local")
- impact (brief)

CVE Data:
{json.dumps(cve, indent=2)}

Return only valid JSON, no explanation."""

        try:
            response = self.groq_client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3,
                max_tokens=500
            )

            summary = response.choices[0].message.content.strip()

            # Try to parse as JSON to validate
            try:
                json.loads(summary)
                return summary
            except json.JSONDecodeError:
                # If Groq didn't return valid JSON, create a basic summary
                return json.dumps({
                    'cve_id': cve.get('cve_id'),
                    'brief_description': cve.get('description', '')[:100],
                    'affected_technologies': cve.get('affected_products', [])[:3],
                    'attack_vector': 'network' if 'network' in cve.get('description', '').lower() else 'unknown',
                    'impact': cve.get('cvss_v3_severity', 'unknown')
                })

        except Exception as e:
            print(f"Error summarizing CVE with Groq: {e}")
            # Return basic summary without Groq
            return json.dumps({
                'cve_id': cve.get('cve_id'),
                'brief_description': cve.get('description', '')[:100],
                'affected_technologies': cve.get('affected_products', [])[:3],
                'attack_vector': 'unknown',
                'impact': cve.get('cvss_v3_severity', 'unknown')
            })

    def _process_cve_batch(self, raw_cves: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Process a batch of raw CVEs through enrichment and summarization.

        Args:
            raw_cves: List of raw CVE dictionaries from NVD

        Returns:
            List of processed CVE dictionaries
        """
        processed_cves = []

        print(f"Processing {len(raw_cves)} CVEs...")

        # Enrich with OTX
        print("Enriching with OTX...")
        otx_enrichment = self.otx_client.batch_enrich_cves(raw_cves)

        # Process each CVE
        for i, cve in enumerate(raw_cves):
            if i % 10 == 0:
                print(f"  Processing CVE {i+1}/{len(raw_cves)}...")

            cve_id = cve.get('cve_id')

            # Get OTX enrichment
            enrichment = otx_enrichment.get(cve_id, {})

            # Summarize with Groq
            summary_json = self._summarize_cve_with_groq(cve)
            summary = json.loads(summary_json)

            # Combine into final CVE record
            processed_cve = {
                'cve_id': cve_id,
                'description': cve.get('description'),
                'summary': summary,
                'cvss_v3_score': cve.get('cvss_v3_score'),
                'cvss_v3_severity': cve.get('cvss_v3_severity'),
                'cvss_v2_score': cve.get('cvss_v2_score'),
                'affected_products': cve.get('affected_products', []),
                'published_date': cve.get('published_date'),
                'modified_date': cve.get('modified_date'),
                'otx_pulse_count': enrichment.get('pulse_count', 0),
                'otx_malware_families': enrichment.get('malware_families', []),
                'otx_active_exploitation': enrichment.get('active_exploitation', False),
                'otx_first_seen': enrichment.get('first_seen'),
                'otx_last_seen': enrichment.get('last_seen')
            }

            processed_cves.append(processed_cve)

        return processed_cves

    def _fetch_and_process_cves(self):
        """Fetch new CVEs and process them."""
        print(f"\n[{datetime.now().isoformat()}] CVE Agent: Fetching new CVEs...")

        # Determine fetch window
        if self.last_fetch_time:
            start_date = self.last_fetch_time
        else:
            start_date = self.start_date

        # Fetch CVEs from NVD
        raw_cves = self.nvd_client.fetch_cves_delta(
            start_date=start_date,
            max_results=2000
        )

        if not raw_cves:
            print("No new CVEs found.")
            return

        print(f"Fetched {len(raw_cves)} CVEs from NVD")

        # Process CVEs
        processed_cves = self._process_cve_batch(raw_cves)

        # Update shared state
        current_state = self._read_shared_state()
        existing_cve_ids = {cve['cve_id'] for cve in current_state['cves']}

        # Add only new CVEs
        new_cves = [cve for cve in processed_cves if cve['cve_id'] not in existing_cve_ids]

        if new_cves:
            print(f"Adding {len(new_cves)} new CVEs to shared state")
            current_state['cves'].extend(new_cves)

            # Update metadata
            current_state['last_updated'] = datetime.now().isoformat()
            current_state['metadata']['total_cves'] = len(current_state['cves'])
            current_state['metadata']['last_fetch_count'] = len(new_cves)

            # Write to file
            self._write_shared_state(current_state)

            print(f"Shared state updated. Total CVEs: {current_state['metadata']['total_cves']}")
        else:
            print("No new CVEs to add to shared state")

        # Update last fetch time
        self.last_fetch_time = datetime.now()

    def _run_loop(self):
        """Main agent loop."""
        while self.running:
            try:
                self._fetch_and_process_cves()
            except Exception as e:
                print(f"Error in CVE agent loop: {e}")

            # Wait for next check
            time.sleep(self.check_interval)

    def start(self):
        """Start the background CVE agent."""
        if self.running:
            print("CVE agent is already running")
            return

        print("Starting CVE agent...")
        self.running = True

        # Start in background thread
        self.thread = threading.Thread(target=self._run_loop, daemon=True)
        self.thread.start()

        print(f"CVE agent started (checking every {self.check_interval}s)")

    def stop(self):
        """Stop the background CVE agent."""
        if not self.running:
            return

        print("Stopping CVE agent...")
        self.running = False

        if self.thread:
            self.thread.join(timeout=5)

        print("CVE agent stopped")

    def fetch_once(self):
        """Fetch CVEs once without starting the background thread."""
        self._fetch_and_process_cves()


if __name__ == "__main__":
    # Test the agent
    agent = CloudCVEAgent(check_interval=60)

    # Fetch once for testing
    agent.fetch_once()

    # Or start continuous monitoring
    # agent.start()
    # try:
    #     while True:
    #         time.sleep(1)
    # except KeyboardInterrupt:
    #     agent.stop()
