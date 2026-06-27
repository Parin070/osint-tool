from .base import Recon
from ddgs import DDGS
from bs4 import BeautifulSoup
import whois
import tldextract
import dns.resolver
import requests
import os
import re

class DomainRecon(Recon):

    def run(self):
        #Whois
        who = whois.whois(self.target)

        #DNS
        try:
            mx_records = dns.resolver.resolve(self.target, "MX")
            mx_list = [r.to_text() for r in mx_records]
        except Exception:
            mx_list = []

        try:
            txt_records = dns.resolver.resolve(self.target, "TXT")
            txt_list = [r.to_text() for r in txt_records]
        except Exception:
            txt_list = []

        try:
            a_records = dns.resolver.resolve(self.target, "A")
            a_list = [r.to_text() for r in a_records]
        except Exception:
            a_list = []

        #crt.sh
        try:
            response = requests.get(f"https://crt.sh/?q={self.target}&output=json").json()
            subdomains = set()
            for entry in response:
                subdomains.add(entry["name_value"])
            subdomains = list(subdomains)[:20]
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
        self._run_financial_dork()
        self._fetch_financial_content()

    def calculate_risk(self):
        vt_stats = self.results["VirusTotal"]["data"]["attributes"]["last_analysis_stats"]
        vt_score = (vt_stats["malicious"] / sum(vt_stats.values())) * 100
        self.results["risk_score"] = round(vt_score, 2)

    def _run_company_check(self):
        org = self.results["Whois"].get("Org")
        if not org or len(org) < 3:
            org = self._extract_name_from_domain()

        domain_name = tldextract.extract(self.target).domain.lower()
        if domain_name not in org.lower():
            org = self._extract_name_from_domain()
        
        proxy_keywords = ["privacy", "proxy", "protect", "whoisguard", "domains by proxy", "redacted"]
        if any(kw in org.lower() for kw in proxy_keywords):
            org = self._extract_name_from_domain()

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
    
    def _run_financial_dork(self):
        org = self.results["Whois"].get("Org")
        if not org or len(org) < 3:
            org = self._extract_name_from_domain()

        domain_name = tldextract.extract(self.target).domain.lower()
        if domain_name not in org.lower():
            org = self._extract_name_from_domain()
        
        proxy_keywords = ["privacy", "proxy", "protect", "whoisguard", "domains by proxy", "redacted"]
        if any(kw in org.lower() for kw in proxy_keywords):
            org = self._extract_name_from_domain()

        query = f'"{org}" OR "{self.target}" revenue OR "annual report" OR "financial results" OR earnings'

        links = []
        try:
            with DDGS() as ddgs:
                results = ddgs.text(query, max_results=5)
                for r in results:
                    links.append({
                        "title": r.get("title", ""),
                        "url": r.get("href", ""),
                        "snippet": r.get("body", "")[:150]
                    })
        except Exception as e:
            links.append({"error": str(e)})

        self.results["FinancialDork"] = {
            "Org": org,
            "Results": links
        }

    def _fetch_financial_content(self):
        fd = self.results.get("FinancialDork", {})
        if "error" in fd or "Results" not in fd:
            self.results["FinancialContent"] = ""
            return
    
        urls = [r["url"] for r in self.results["FinancialDork"]["Results"] if "url" in r]
    
        combined_text = ""
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"}
    
        for url in urls[:3]:  # top 3 only
            try:
                response = requests.get(url, headers=headers, timeout=8)
                soup = BeautifulSoup(response.text, "html.parser")
                for tag in soup(["script", "style", "nav", "footer"]):
                    tag.decompose()
                text = soup.get_text(separator=" ", strip=True)[:2000]
                combined_text += f"\n\nSOURCE: {url}\n{text}"
            except Exception:
                continue
    
        self.results["FinancialContent"] = combined_text

    def _extract_name_from_domain(self):
        extracted = tldextract.extract(self.target)
        return extracted.domain.capitalize()