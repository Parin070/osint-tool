from .base import Recon
import os
import requests
import json

class IPRecon(Recon):

    def run(self):
        url = 'https://api.abuseipdb.com/api/v2/check'

        querystring = {
            'ipAddress': self.target,
            'maxAgeInDays': '90'
        }

        headers = {
            'Accept': 'application/json',
            'Key': os.getenv("ABUSEIPDB")
        }

        response = requests.get(url, headers=headers, params=querystring)
        self.results = response.json()