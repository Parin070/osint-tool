from .base import Recon
import whois
import dns.resolver
import requests
import os
import re

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
        try:
            response = requests.get(f"https://crt.sh/?q={self.target}&output=json").json()
            subdomains = set()
            for entry in response:
                subdomains.add(entry["name_value"])
            subdomains = list(subdomains)[:20]
            for entry in response:
                subdomains.add(entry["name_value"])
        except Exception:
            subdomains = set()

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
                "Org": who.org,
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
        self._run_company_check()

    def calculate_risk(self):
        vt_stats = self.results["VirusTotal"]["data"]["attributes"]["last_analysis_stats"]
        vt_score = (vt_stats["malicious"] / sum(vt_stats.values())) * 100
        self.results["risk_score"] = round(vt_score, 2)

    def _run_company_check(self):
        org = self.results["Whois"].get("Org")
        if not org:
            self.results["Company"] = {"error": "No org found in Whois"}
            return

        cleaned_org = self._clean_org(org)
        
        try:
            response = requests.get(
                "https://api.gleif.org/api/v1/lei-records",
                params={
                    "filter[entity.legalName]": cleaned_org,
                    "page[size]": 1
                },
                headers={"Accept": "application/vnd.api+json"},
                timeout=10
            )
            data = response.json()
            records = data.get("data", [])

            if not records:
                self.results["Company"] = {"error": "No records found", "org": org}
                return

            top = records[0]["attributes"]["entity"]
            reg = records[0]["attributes"]["registration"]

            self.results["Company"] = {
                "Name": top["legalName"]["name"],
                "Status": top["status"],
                "Jurisdiction": top.get("jurisdiction", "N/A"),
                "Category": top.get("category", "N/A"),
                "Country": top["legalAddress"]["country"],
                "HQ City": top["headquartersAddress"].get("city", "N/A"),
                "LEI Status": reg["status"],
                "Last Updated": reg["lastUpdateDate"],
                "Next Renewal": reg["nextRenewalDate"],
                "Corroboration": reg["corroborationLevel"]
            }

        except Exception as e:
            self.results["Company"] = {"error": str(e)}
    
    def _clean_org(self, org):
        suffixes = r'\b(LLC|Inc\.?|Ltd\.?|Corp\.?|Co\.?|Limited|Incorporated|Corporation|GmbH|PLC|AG)\b'
        cleaned = re.sub(suffixes, '', org, flags=re.IGNORECASE).strip().strip(',').strip()
        return cleaned