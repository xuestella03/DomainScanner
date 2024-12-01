import json
import sys
import time
from typing import Dict, Any, List
from pathlib import Path

# from domain_scanner import DomainScanner
import sys
sys.path.append(str(Path(__file__).parent / "src"))
from domain_scanner.scanners.dns_scanner import DNSScanner
from domain_scanner.scanners.http_scanner import HTTPScanner

class DomainScanner:
    def __init__(self):
        self.dns_scanner = DNSScanner()
        self.http_scanner = HTTPScanner()

    # check naming of this next one. should it be scan.py?
    def scan_domain(self, domain:str) -> Dict[str, Any]:
        """
        :param domain:
        :return: results as dictionary
        """

        # 5.1: scan_time
        results = {
            "scan_time": time.time()
        }


        # now do the actual scans here

        # 5.2: ipv4_addresses
        try:
            ipv4_addr = self.dns_scanner.get_ipv4_addr(domain)
            results["ipv4_addresses"] = ipv4_addr
        except Exception as e:
            print(f"error ipv4: {e}", file=sys.stderr)

        # 5.3: ipv5_addresses
        try:
            ipv6_addr = self.dns_scanner.get_ipv6_addr(domain)
            results["ipv6_addresses"] = ipv6_addr
        except Exception as e:
            print(f"error ipv6: {e}", file=sys.stderr)

        # 5.4: http_server
        try:
            http_server = self.http_scanner.http_server(domain)
            results["http_server"] = http_server
        except Exception as e:
            print(f"error http server: {e}", file=sys.stderr)

        # 5.5: insecure_http
        # 5.6: redirect_to_https
        # 5.7: hsts
        # 5.8: tls_versions
        # 5.9:
        # 5.10:
        # 5.11:
        # 5.12:

        return results

    def scan_from_file(self, input_file: str, output_file: str) -> None:
        """
        :param input_file:
        :param output_file:
        :return: write results to output file
        """

        # read domains
        with open(input_file, 'r') as f:
            domains = [line.strip() for line in f if line.strip()]

        # scan each domain
        results = {}
        for domain in domains:
            results[domain] = self.scan_domain(domain)

        # write results
        with open(output_file, 'w') as f:
            json.dump(results, f, sort_keys=True, indent=4)

def main():
    import sys
    if len(sys.argv) != 3:
        print("Usage: python scan_domain.py <input_file> <output_file>")
        sys.exit(1)
    scanner = DomainScanner()
    scanner.scan_from_file(sys.argv[1], sys.argv[2])

if __name__ == "__main__":
    main()
