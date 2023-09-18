# This module is only going to make API calls make a list of all the fixed vulnerabilities that it can see from the Acunetix API Call
import json
import os
import requests


class API:
    def __init__(self):
        headers = {
            'Accept': 'application/json',
            'X-Auth': '<add api key here>',
        }
        r = requests.get('https://10.250.0.72:3443/api/v1/vulnerabilities', headers=headers,
                         verify=False)
        vulnerabilities = r.json()['vulnerabilities']
        fixed_vids_files = f"/opt/wazuh_logging/acunetix/Fixed_vulnerabilities.txt"
        active_vulnerabilities_id = "/opt/wazuh_logging/acunetix/active_vulnerabilities_id.txt"
        logfile = "/opt/wazuh_logging/acunetix/notfixed/notfixed_vuln.log"
        fixed_vulns = "/opt/wazuh_logging/acunetix/fixed/fixed_vuln.log"
        if os.path.isfile(logfile):
            os.remove(logfile)
        if os.path.isfile(fixed_vulns):
            os.remove(fixed_vulns)
        self.fixed_vids_files = fixed_vids_files
        self.logfile = logfile
        self.fixed_vulns = fixed_vulns
        self.vulnerabilities = vulnerabilities
        self.active_vulnerabilities_id = active_vulnerabilities_id

    def get_fixed_vulnerabilities(self):
        fixed_vulns = self.fixed_vulns
        fixed_vids_files = self.fixed_vids_files
        vulnerabilities = self.vulnerabilities
        if os.path.isfile(fixed_vids_files):
            # logic to get the old vt_ids
            vid_list = []
            with open(fixed_vids_files, "r") as fixed_vid:
                vid = fixed_vid.readlines()
                if os.path.isfile(fixed_vulns):
                    print("true")
                    os.remove(fixed_vulns)
                for line in vid:
                    vid_list.append(line.replace("\n", ""))
            # once the list of old vuln list is generated it will be comapred with the new list to make sure we do not write any new vulns down
            with open(fixed_vulns, 'x') as logs_file:
                for vulnerability in vulnerabilities:
                    if vulnerability["vuln_id"] not in vid_list:
                        if vulnerability["status"] == "fixed":
                            with open(fixed_vulns, "a") as write_file:
                                vulnerability['Log_type'] = 'acunetix'
                                json.dump(vulnerability, write_file)
                                write_file.write('\n')
                            with open(fixed_vids_files, "a") as write_file:
                                write_file.write(vulnerability["vuln_id"] + "\n")

        else:
            with open(fixed_vulns, 'x') as logs_file:
                with open(fixed_vids_files, 'x') as fixed_vuln_file:
                    for vulnerability in vulnerabilities:
                        if vulnerability["status"] == "fixed":
                            with open(fixed_vulns, "a") as write_file:
                                vulnerability['Log_type'] = 'acunetix'
                                json.dump(vulnerability, write_file)
                                write_file.write('\n')
                            with open(fixed_vids_files, "a") as write_file:
                                write_file.write(vulnerability["vuln_id"] + "\n")

    def get_not_fixed_vulnerabilities(self):
        active_vulnerabilities_id = self.active_vulnerabilities_id
        vulnerabilities = self.vulnerabilities
        logfile = self.logfile
        if os.path.isfile(logfile):
            print("true")
            os.remove(logfile)
        if os.path.isfile(active_vulnerabilities_id):
            # logic to get the old vt_ids
            vid_list = []
            with open(active_vulnerabilities_id, "r") as active_vid:
                vid = active_vid.readlines()
                for line in vid:
                    vid_list.append(line.replace("\n", ""))
            # once the list of old vuln list is generated it will be comapred with the new list to make sure we do not write any new vulns down
            with open(logfile, 'x') as logs_file:
                for vulnerability in vulnerabilities:
                    print(type(vulnerability))
                    if vulnerability["vuln_id"] not in vid_list:
                        if vulnerability["status"] != "fixed":
                            with open(logfile, "a") as write_file:
                                vulnerability['Log_type'] = 'acunetix'
                                json.dump(vulnerability, write_file)
                                write_file.write('\n')
                            with open(active_vulnerabilities_id, "a") as write_file:
                                write_file.write(vulnerability["vuln_id"] + "\n")
        else:
            with open(logfile, 'x') as logs_file:
                with open(active_vulnerabilities_id, 'x') as logs_text_file:
                    for vulnerability in vulnerabilities:
                        if vulnerability["status"] != "fixed":
                            with open(logfile, "a") as write_file:
                                print(type(vulnerability))
                                vulnerability['Log_type'] = 'acunetix'
                                json.dump(vulnerability, write_file)
                                write_file.write('\n')
                            with open(active_vulnerabilities_id, "a") as write_file:
                                write_file.write(vulnerability["vuln_id"] + "\n")


def main():
    lets_run_it = API()
    lets_run_it.get_fixed_vulnerabilities()
    lets_run_it.get_not_fixed_vulnerabilities()


main()
