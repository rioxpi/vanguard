import json
import subprocess
import sys
import xml.etree.ElementTree as ET
from core.config import DIRECTORIES

class DirectoryFuzzer:
    """A class to handle directory fuzzing using ffuf and parsing the results."""

    def start_fuzzing(self, target: str) -> list:
        """Runs ffuf against the specified target.

        Args:
            target (str): The target to scan
        """
        self.run_ffuf(target)
        print(f"Parsing ffuf results for {target}...")
        parsed_results = self.parse_ffuf_json(open('ffuf_output.json').read())
        return parsed_results
    
    @staticmethod
    def parse_ffuf_json(json_data: str) -> list:
        """Parses the ffuf JSON output and extracts found URLs.

        Args:
            json_data (str): The JSON output from ffuf as a string.

        Returns:
            list: A list of found URLs.
        """
        print("Parsing ffuf JSON output...")
        found_urls = []
        try:
            data = json.loads(json_data)
            for result in data.get('results', []):
                url = result.get('url')
                if url:
                    found_urls.append(url)
        except json.JSONDecodeError as e:
            print(f"Error parsing JSON: {e}")
        
        return found_urls

    @staticmethod
    def run_ffuf(target: str) -> None:
        """Runs ffuf against the specified target.

        Args:
            target (str): The target to scan
        """
        try:
            subprocess.run([DIRECTORIES["ffuf"], '-u', f'{target}/FUZZ', '-w', DIRECTORIES["wordlist"], '-o', 'ffuf_output.json', '-of', 'json'], check=True, capture_output=True, text=True)
        except FileNotFoundError:
            print("ffuf is not installed. Please run install.py to download and set up ffuf.")
            sys.exit(1)
        except Exception as e:
            print(f"An error occurred while running ffuf: {e}")
            sys.exit(1)