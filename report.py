import json
import sys
from texttable import Texttable
from collections import Counter

def generate_report(input_file, output_file):

    with open(input_file, "r") as f:
        data = json.load(f)

    # domain info
    domain_sections = []
    for domain, details in data.items():
        domain_section = f"Domain: {domain}\n"
        domain_section += "\n".join([f"  {key}: {value}" for key, value in details.items()])
        domain_sections.append(domain_section)

    # rtt ranges
    rtt_table = Texttable()
    rtt_table.add_row(["Domain", "Min RTT (ms)", "Max RTT (ms)"])
    rtt_ranges = []
    for domain, details in data.items():
        min_rtt, max_rtt = details.get("rtt_range", [None, None])
        rtt_ranges.append((min_rtt, domain, max_rtt))
    rtt_ranges.sort()
    for min_rtt, domain, max_rtt in rtt_ranges:
        rtt_table.add_row([domain, min_rtt, max_rtt])

    # root ca
    root_ca_counts = Counter(details.get("root_ca") for details in data.values())
    root_ca_table = Texttable()
    root_ca_table.add_row(["Root CA", "Occurrences"])
    for ca, count in root_ca_counts.most_common():
        root_ca_table.add_row([ca, count])

    # http server
    http_server_counts = Counter(details.get("http_server") for details in data.values())
    http_server_table = Texttable()
    http_server_table.add_row(["HTTP Server", "Occurrences"])
    for server, count in http_server_counts.most_common():
        http_server_table.add_row([server, count])

    # percentages
    total_domains = len(data)
    feature_counts = {
        "plain_http": sum(1 for d in data.values() if d.get("insecure_http")),
        "https_redirect": sum(1 for d in data.values() if d.get("redirect_to_https")),
        "hsts": sum(1 for d in data.values() if d.get("hsts")),
        "ipv6": sum(1 for d in data.values() if d.get("ipv6_addresses")),
    }
    tls_versions = Counter(tls for details in data.values() for tls in details.get("tls_versions", []))
    feature_table = Texttable()
    feature_table.add_row(["Feature", "Percentage"])
    for feature, count in feature_counts.items():
        feature_table.add_row([feature, f"{(count / total_domains) * 100:.2f}%"])
    for tls, count in tls_versions.items():
        feature_table.add_row([tls, f"{(count / total_domains) * 100:.2f}%"])

    # generate
    with open(output_file, "w") as outfile:
        outfile.write("Report Summary\n\n")
        outfile.write("Domain Information\n")
        outfile.write("\n\n".join(domain_sections))
        outfile.write("\n\nRTT Ranges\n")
        outfile.write(rtt_table.draw())
        outfile.write("\n\nRoot Certificate Authorities\n")
        outfile.write(root_ca_table.draw())
        outfile.write("\n\nHTTP Server Occurrences\n")
        outfile.write(http_server_table.draw())
        outfile.write("\n\nFeature Support\n")
        outfile.write(feature_table.draw())
        outfile.write("\n")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 report.py [input_file.json] [output_file.txt]")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]
    generate_report(input_file, output_file)
