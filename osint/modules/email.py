from .base import Recon
import requests
import re

class EmailRecon(Recon):
    def run(self):
        if self.validate_email():
            response = requests.get(f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email={self.target}")
            data = response.json()
        
            self.results = {
                "Hudson Rock": data
            }
        else:
            self.results = {
                "error": "Invalid email format"
            }

        self.calculate_risk()

    def calculate_risk(self):
        if "error" in self.results:
            self.results["risk_score"] = 0
            return
    
        breach_count = self.results["Hudson Rock"].get("total_user_services", 0)
    
        if breach_count == 0:
            risk_score = 0
        elif breach_count < 10:
            risk_score = 30
        elif breach_count < 50:
            risk_score = 60
        else:
            risk_score = 100
    
        self.results["risk_score"] = risk_score

    def validate_email(self):
        pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        return bool(re.match(pattern, self.target))