"""Verify if CVEs are actually false positives or real matches."""

import nvdlib

# Test a few CVEs from the user's results
test_cves = [
    'CVE-2019-11323',  # haproxy
    'CVE-2016-0742',  # nginx
    'CVE-2021-39226',  # grafana
    'CVE-2015-4335',  # redis
    'CVE-2005-0245',  # postgres
]

print("=" * 80)
print("CVE VERIFICATION - Checking CPE Data")
print("=" * 80)

for cve_id in test_cves:
    print(f"\n[CHECKING] {cve_id}")
    print("-" * 80)

    try:
        # Fetch CVE details from NVD
        cve = nvdlib.searchCVE(cveId=cve_id, key=None)[0]

        # Description
        print(f"\nDescription:")
        print(f"  {cve.descriptions[0].value[:200]}...")

        # CPE data
        print(f"\n[CPE DATA] What products are ACTUALLY affected:")

        if hasattr(cve, 'configurations') and cve.configurations:
            found_cpe = False
            for config in cve.configurations:
                for node in config.nodes:
                    if hasattr(node, 'cpeMatch'):
                        for cpe_match in node.cpeMatch:
                            cpe_string = cpe_match.criteria
                            print(f"  * {cpe_string}")

                            # Parse CPE
                            parts = cpe_string.split(':')
                            if len(parts) >= 6:
                                vendor = parts[3]
                                product = parts[4]
                                version = parts[5]
                                print(f"    -> Vendor: {vendor}")
                                print(f"    -> Product: {product}")
                                print(f"    -> Version: {version}")

                                # Check version ranges
                                if hasattr(cpe_match, 'versionEndIncluding'):
                                    print(f"    -> Affected up to: {cpe_match.versionEndIncluding}")
                                if hasattr(cpe_match, 'versionStartIncluding'):
                                    print(f"    -> Affected from: {cpe_match.versionStartIncluding}")

                            found_cpe = True
                            print()

            if not found_cpe:
                print("  WARNING: No CPE data found - this is suspicious!")
        else:
            print("  WARNING: No CPE data found - this is suspicious!")

    except Exception as e:
        print(f"  ERROR: {e}")

print("\n" + "=" * 80)
print("ANALYSIS")
print("=" * 80)

print("""
How to verify if CVE is real match:
1. Check CPE data (official product/version info from NVD)
2. Look for exact product name match
3. Check version ranges match your component version
4. Beware of CVEs that "mention" product but don't affect it

False positive indicators:
- CVE description mentions product but CPE is for something else
- CVE is for a plugin/wrapper, not the core product
- CVE is for a different vendor with similar name
- Version ranges don't match
""")
