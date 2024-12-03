from typing import List, Optional, Tuple
from .base import Base
import re
import subprocess
# import maxminddb

class MoreScanners(Base):
    def __init__(self, geodb_path: str = "GeoLite2-City.mmdb"):
        super().__init__()
        # self.geodb = maxminddb.open_file(geodb_path)

    def tls_versions(self, domain: str) -> List[str]:
        versions = {
            "ssl2": ("-ssl2", "SSLv2"),
            "ssl3": ("-ssl3", "SSLv3"),
            "tls1.0": ("-tls1", "TLSv1.0"),
            "tls1.1": ("-tls1_1", "TLSv1.1"),
            "tls1.2": ("-tls1_2", "TLSv1.2"),
            "tls1.3": ("-tls1_3", "TLSv1.3")
        }
        supported = []

        for version, (flag, name) in versions.items():
            command = ["openssl", "s_client", flag, "-connect", f"{domain}:443"]
            result = self.run_command(command, input_data=b'', suppress_errors = True)
            if result and "BEGIN CERTIFICATE" in result:
                supported.append(name)

        return sorted(supported)

    def root_ca(self, domain: str) -> Optional[str]:
        command = ["openssl", "s_client", "-connect", f"{domain}:443"]
        result = self.run_command(command, input_data=b'')

        if not result:
            return None

        # Parse the output for O=<org> in the issuer field
        for line in result.splitlines():
            if "O =" in line:
                return line.split("O =")[-1].strip()
        return None

    def rdns_names(self, ip_addresses: List[str]) -> List[str]:
        res = []
        for addr in ip_addresses:
            # command = ["dig", "-x", addr]
            command = ["nslookup", addr]
            result = self.run_command(command)

            # print(f"rdns result: {result}")

            if result:
                for line in result.splitlines():
                    if line.lower().startswith("name"):
                        # print("hello")
                        dns_name = line.strip().split()[-1]
                        # print(f"dns name: {dns_name}")
                        res.append(dns_name)
        return res

    def rtt_range(self, ip_addresses: List[str]):
        # min_time = float('inf')
        # max_time = 0
        # for addr in ip_addresses:
        #     for port in ["80", "22", "443"]:
        #         # command = ["sh", "-c", "\"time", "echo", "-e", "'\x1dclose\ x0d'", "|", "telnet", addr, port, "\""]
        #         # command = ["sh -c \"time echo -e \'\\x1dclose\\x0d\' | telnet", addr, port, "\""]
        #         # command = f'sh -c "time echo -e \'\\x1dclose\\x0d\' | telnet {addr} {port}"'
        #         # command = f"sh -c \"time echo -e '\\x1dclose\\x0d' | telnet {addr} {port}\""
        #         addr2 = addr.replace(":", ".")
        #         command = [f"telnet{addr2} {port}"]
        #         print(command)
        #         result = self.run_command(command)
        #         # result = subprocess.call(
        #         #     command,
        #         #     timeout=2,
        #         #     stderr=subprocess.STDOUT,
        #         #     stdout=subprocess.PIPE,
        #         #     text=True
        #         # )
        #         print("hello", result)
        #         # match = re.search(r"real\s+(\d+)m(\d+\.\d+)s", result)
        #         # if match:
        #         #     minutes = int(match.group(1))
        #         #     seconds = float(match.group(2))
        #         #     rtt = (minutes * 60 + seconds) * 1000  # Convert to milliseconds
        #         #
        #         #     # Update min and max RTT
        #         #     min_time = min(min_time, rtt)
        #         #     max_time = max(max_time, rtt)
        #
        # return [min_time, max_time]
        pass

    def geo_locations(self, ip_addresses: List[str]) -> List[str]:
        pass

    def close_db(self):
        pass

