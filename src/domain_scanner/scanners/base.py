import subprocess
from typing import List

class Base:
    """
    Functions to run a scanner
    """
    def __init__(self):
        pass

    def run_command(self, command: List[str], input_data: bytes = None, suppress_errors: bool = False):
        """
        :param command: command specific to the scanner
        :param input_data: if you want the echo
        :return: result of the command
        """
        try:
            result = subprocess.check_output(command, timeout=2, stderr=subprocess.STDOUT, input=input_data).decode("utf-8")
            return result
        except subprocess.CalledProcessError as e:
            if not suppress_errors:
                print(f"Failed: {command}")
            return None
        except subprocess.TimeoutExpired as e:
            print(f"Timeout: {command}")
            return None
        except FileNotFoundError as e:
            print(f"FileNotFound: {command}")
            return None
