import json
import os
import requests
from configparser import ConfigParser


class API:
    """
    A class to interact with Acunetix API and gather information about vulnerabilities.
    """

    def __init__(self, config_file: str):
        """
        Initializes the API object with configurations from a file and fetches the vulnerabilities.
        
        :param config_file: Path to the configuration file containing necessary parameters.
        """
        # Loading configurations from the configuration file
        config = ConfigParser()
        config.read(config_file)

        # Setting headers and fetching vulnerabilities from the Acunetix API
        headers = {'Accept': 'application/json', 'X-Auth': config.get('Acunetix', 'api_key')}
        url = config.get('Acunetix', 'url')
        r = requests.get(url, headers=headers, verify=False)
        vulnerabilities = r.json().get('vulnerabilities', [])

        # Assigning configuration paths to instance variables
        self.fixed_vids_files = config.get('Acunetix', 'fixed_vids_files')
        self.active_vulnerabilities_id = config.get('Acunetix', 'active_vulnerabilities_id')
        self.logfile = config.get('Acunetix', 'logfile')
        self.fixed_vulns = config.get('Acunetix', 'fixed_vulns')
        self.vulnerabilities = vulnerabilities

    def get_fixed_vulnerabilities(self):
        """
        Identifies and logs the newly fixed vulnerabilities.
        """
        # Reads existing fixed vulnerabilities ids
        vid_list = []
        if os.path.isfile(self.fixed_vids_files):
            with open(self.fixed_vids_files, "r") as fixed_vid:
                vid_list = [line.strip() for line in fixed_vid.readlines()]

        # Logs newly fixed vulnerabilities and updates the list of fixed vulnerability ids
        with open(self.fixed_vulns, 'a') as logs_file, open(self.fixed_vids_files, "a") as vid_file:
            for vulnerability in self.vulnerabilities:
                if vulnerability["vuln_id"] not in vid_list and vulnerability["status"] == "fixed":
                    vulnerability['Log_type'] = 'acunetix'
                    json.dump(vulnerability, logs_file)
                    logs_file.write('\n')
                    vid_file.write(vulnerability["vuln_id"] + "\n")

    def get_not_fixed_vulnerabilities(self):
        """
        Identifies and logs the vulnerabilities that are not fixed.
        """
        # Reads existing not fixed vulnerabilities ids
        vid_list = []
        if os.path.isfile(self.active_vulnerabilities_id):
            with open(self.active_vulnerabilities_id, "r") as active_vid:
                vid_list = [line.strip() for line in active_vid.readlines()]

        # Logs newly found not fixed vulnerabilities and updates the list of not fixed vulnerability ids
        with open(self.logfile, 'a') as logs_file, open(self.active_vulnerabilities_id, "a") as vid_file:
            for vulnerability in self.vulnerabilities:
                if vulnerability["vuln_id"] not in vid_list and vulnerability["status"] != "fixed":
                    vulnerability['Log_type'] = 'acunetix'
                    json.dump(vulnerability, logs_file)
                    logs_file.write('\n')
                    vid_file.write(vulnerability["vuln_id"] + "\n")


def main():
    """
    The main function to run the API calls and associated methods.
    """
    acunetix_api = API('key.cfg')
    acunetix_api.get_fixed_vulnerabilities()
    acunetix_api.get_not_fixed_vulnerabilities()


if __name__ == "__main__":
    main()

