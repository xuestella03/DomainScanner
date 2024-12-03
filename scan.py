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
from domain_scanner.scanners.other_scanners import MoreScanners

class DomainScanner:
    def __init__(self):
        self.dns_scanner = DNSScanner()
        self.http_scanner = HTTPScanner()
        self.other_scanners = MoreScanners()

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

        # 5.3: ipv6_addresses
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
        try:
            insecure_http = self.http_scanner.insecure_http(domain)
            results["insecure_http"] = insecure_http
        except Exception as e:
            print(f"error insecure http: {e}", file=sys.stderr)

        # 5.6: redirect_to_https
        try:
            redirect_to_https = self.http_scanner.redirect_to_https(domain)
            results["redirect_to_https"] = redirect_to_https
        except Exception as e:
            print(f"error redirect to https: {e}", file=sys.stderr)

        # 5.7: hsts
        try:
            hsts = self.http_scanner.hsts(domain)
            results["hsts"] = hsts
        except Exception as e:
            print(f"error hsts: {e}", file=sys.stderr)

        # 5.8: tls_versions
        try:
            tls_versions = self.other_scanners.tls_versions(domain)
            results["tls_versions"] = tls_versions
        except Exception as e:
            print(f"error tls versions: {e}", file=sys.stderr)

        # 5.9: root_ca
        try:
            root_ca = self.other_scanners.root_ca(domain)
            results["root_ca"] = root_ca
        except Exception as e:
            print(f"error root ca: {e}", file=sys.stderr)

        # 5.10: rdns_names
        try:
            ip_addresses = self.dns_scanner.get_ipv4_addr(domain)
            rdns_names = self.other_scanners.rdns_names(ip_addresses)
            results["rdns_names"] = rdns_names
        except Exception as e:
            print(f"error rdns names: {e}", file=sys.stderr)

        # 5.11: rtt_range
        try:
            ip_addresses = self.dns_scanner.get_ipv4_addr(domain)
            rtt_range = self.other_scanners.rtt_range(ip_addresses)
            results["rtt_range"] = rtt_range
        except Exception as e:
            print(f"error rtt: {e}", file=sys.stderr)

        # 5.12: geo_locations
        results["geo_locations"] = ["ph"]

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
    # resolvers_file = Path(__file__).parent / "public_dns_resolvers.txt"
    # scanner.dns_scanner.get_resolvers(resolvers_file)
    scanner.scan_from_file(sys.argv[1], sys.argv[2])

if __name__ == "__main__":
    main()
