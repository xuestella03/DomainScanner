from typing import Optional, Dict
from .base import Base
import socket
import ssl

class HTTPScanner(Base):
    def __init__(self):

        super().__init__()

    def http_server(self, domain: str) -> Optional[str]:
        """
        part 5.4: returns the server header
        :param domain:
        :return:
        """

        # send get request
        request = f"GET / HTTP/1.1\r\n"
        request += f"Host: {domain}\r\n"
        request += f"User-Agent: Mozilla/5.0\r\n"
        request += f"Accept: */*\r\n"
        request += f"Connection: close\r\n\r\n"

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((domain, 80))
            sock.send(request.encode())

            # iterate through received and add to the response
            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk

            # decode response
            header_bytes = response.split(b'\r\n\r\n')[0]
            header_entries = header_bytes.split(b'\r\n')

            for entry in header_entries:
                if entry.lower().startswith(b'server:'):
                    decoded_entry = entry.decode('utf-8')
                    return decoded_entry.split(':',1)[1].strip()

        except socket.error:
            pass

        finally:
            sock.close()

        return None

    def insecure_http(self, domain: str):
        """
        part 5.5: returns boolean indicating whether the website listens
            for unencrypted HTTP requests on port 80
        :param domain:
        :return: boolean
        """
        
        # unencrypted HTTP requests will be on port 80.
        # so check if the connection succeeds on port 80.
        # if it doesn't will be HTTPS
        # send get request
        request = f"GET / HTTP/1.1\r\n"
        request += f"Host: {domain}\r\n"
        request += f"User-Agent: Mozilla/5.0\r\n"
        request += f"Accept: */*\r\n"
        request += f"Connection: close\r\n\r\n"

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((domain, 80))
            sock.send(request.encode())

            # iterate through received and add to the response
            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk

            if response:
                return True
            else:
                return False

        except socket.error:
            pass

        finally:
            sock.close()

        return False

    def redirect_to_https(self, domain: str):
        """
        part 5.6: returns boolean indicating whether unencrypted HTTP
            requests on port 80 are redirected to HTTPS on port 443
        :param domain:
        :return:
        """
        pass

    def hsts(self, domain: str):
        """
        part 5.7: returns boolean indicating whether the website has
            enabled HSTS
        :param domain:
        :return:
        """
        pass