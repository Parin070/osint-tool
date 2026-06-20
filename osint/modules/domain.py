from .base import Recon
import whois
import dns.resolver

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
            }
        }