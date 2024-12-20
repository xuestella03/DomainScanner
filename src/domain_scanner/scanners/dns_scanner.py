from email._header_value_parser import Domain
from typing import List
from .base import Base

class DNSScanner(Base):
    def __init__(self):

        super().__init__()

        # change this to read file
        self.dns_resolvers = ["208.67.222.222", "1.1.1.1", "8.8.8.8", "8.26.56.26", "9.9.9.9", "64.6.65.6", "185.228.168.168"]

    def get_ipv4_addr(self, domain: str) -> List[str]:
        """
        get all ipv4 addr for a domain that uses multiple DNS resolvers
        :param domain:
        :return: list of ipv4 addr as strings
        """
        ip_addresses = set()
        # output = self.dns_lookup(domain, "8.8.8.8", "ipv4")
        # ip_addresses.update(output)
        for r in self.dns_resolvers:
            output = self.dns_lookup(domain, r, "ipv4")
            ip_addresses.update(output)

        return list(ip_addresses)


    def get_ipv6_addr(self, domain: str) -> List[str]:
        """
        get all ipv6 addr for a domain that uses multiple DNS resolvers
        :param domain:
        :return: list of ipv6 addr as strings
        """
        ip_addresses = set()
        for r in self.dns_resolvers:
            output = self.dns_lookup(domain, r, "ipv6")
            ip_addresses.update(output)

        return list(ip_addresses)

    def dns_lookup(self, domain: str, resolver: str, record_type: str) -> List[str]:
        """
        function to run commands and parse output for a given domain and resolver
        :param domain:
        :param resolver:
        :param record_type: this indicates whether it's ipv4 or ipv6;
        :return: list of found IP addresses as strings
        """

        # use run_command from Base class
        if record_type == "ipv4":
            command = ["nslookup", domain, resolver]
        else:
            command = ["nslookup", "-type=AAAA", domain, resolver]

        command_output = self.run_command(command)

        # parse the output
        addresses = []
        # if command_output:
        for line in command_output.splitlines():
            # skip if empty
            if not line.strip():
                continue
            # if line.strip().startswith("Addresses: "):
                # ip = line.strip().split("Addresses: ")[1]
                # addresses.append(ip)
            if line.startswith("Addresses:") or line.startswith("Address:"):
                parts = line.split(": ")
                if len(parts) > 1:
                    addresses.append(parts[1])

        return addresses

    def get_resolvers(self, file) -> None:
        """
        load the list of resolvers from a file
        :param file:
        :return: None
        """
        f = open(file, "r")
        for line in f:
            self.dns_resolvers.append(line.strip())