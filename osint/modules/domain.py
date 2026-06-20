from .base import Recon
import whois
import dns.resolver
import requests
import os

class DomainRecon(Recon):

    def run(self):
        #Whois
        who = whois.whois(self.target)

        #DNS
        a_records = dns.resolver.resolve(self.target, "A")
        mx_records = dns.resolver.resolve(self.target, "MX")
        txt_records = dns.resolver.resolve(self.target, "TXT")
        a_list = [ip.to_text() for ip in a_records]
        mx_list = [ip.to_text() for ip in mx_records]
        txt_list = [ip.to_text() for ip in txt_records]

        #crt.sh
        response = requests.get(f"https://crt.sh/?q={self.target}&output=json").json()
        subdomains = set()
        for entry in response:
            subdomains.add(entry["name_value"]) 

        #VirusTotal
        url_vt = f"https://www.virustotal.com/api/v3/domains/{self.target}"
        headers_vt = {
            "accept": "application/json",
            "x-apikey": os.getenv("VIRUSTOTAL")
        }

        vt_response = requests.get(url_vt, headers=headers_vt).json()

        self.results = {
            "Whois": {
                "Registrar": who.registrar,
                "Creation Date": who.creation_date,
                "Expiration Date": who.expiration_date,
                "Name Servers": who.name_servers
            },
            "DNS": {
                "A": a_list,
                "MX": mx_list,
                "TXT": txt_list
            },
            "Subdomains": list(subdomains),
            "VirusTotal": vt_response
        }
        self.calculate_risk()

    def calculate_risk(self):
        vt_stats = self.results["VirusTotal"]["data"]["attributes"]["last_analysis_stats"]
        vt_score = (vt_stats["malicious"] / sum(vt_stats.values())) * 100
        self.results["risk_score"] = round(vt_score, 2)