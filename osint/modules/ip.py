from .base import Recon
from shodan import Shodan
import os
import requests
import json

class IPRecon(Recon):

    def run(self):
        #AbuseIPDB
        url_ab = 'https://api.abuseipdb.com/api/v2/check'

        querystring = {
            'ipAddress': self.target,
            'maxAgeInDays': '90'
        }

        headers_ab = {
            'Accept': 'application/json',
            'Key': os.getenv("ABUSEIPDB")
        }
        abuse_response = requests.get(url_ab, headers=headers_ab, params=querystring).json()

        #Shodan
        api = Shodan(os.getenv("SHODAN"))
        shodan_response = api.host(self.target)
        
        #VirusTotal
        url_vt = f"https://www.virustotal.com/api/v3/ip_addresses/{self.target}"
        headers_vt = {
            "accept": "application/json",
            "x-apikey": os.getenv("VIRUSTOTAL")
        }

        vt_response = requests.get(url_vt, headers=headers_vt).text

        self.results = {
            "AbuseIPDB": abuse_response,
            "Shodan": shodan_response,
            "VirusTotal": vt_response
        }
        self.calculate_risk()
    
    def calculate_risk(self):
        abuse_score = self.results["AbuseIPDB"]["data"]["abuseConfidenceScore"]
        vt_stats = self.results["VirusTotal"]["data"]["attributes"]["last_analysis_stats"]
        #error in vt stats 
        vt_score = (vt_stats["malicious"]/sum(vt_stats.values())) * 100
        shodan_score = 100 if self.results["Shodan"].get("vulns") else 0

        risk_score = (abuse_score + vt_score + shodan_score)/3
        self.results["risk_score"] = round(risk_score, 2)