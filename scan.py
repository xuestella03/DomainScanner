import json
import sys
import time
from typing import Dict, Any, List
from pathlib import Path

# from domain_scanner import DomainScanner
import sys
sys.path.append(str(Path(__file__).parent / "src"))
from domain_scanner.scanners.dns_scanner import DNSScanner

class DomainScanner:
    def __init__(self):
        self.dns_scanner = DNSScanner()

    # check naming of this next one. should it be scan.py?
    def scan_domain(self, domain:str) -> Dict[str, Any]:
        """
        :param domain:
        :return: results as dictionary
        """
        results = {
            "scan_time": time.time()
        }


        # now do the actual scans here once the scanners are implemented
        try:
            ipv4_addr = self.dns_scanner.get_ipv4_addr(domain)
            results["ipv4_addr"] = ipv4_addr
        except Exception as e:
            print(f"error ipv4: {e}", file=sys.stderr)

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
