from .base import Recon
import whois

class DomainRecon(Recon):

    def run(self):
        #Whois
        who = whois.whois(self.target)

        self.results = {
            "Whois": {
                "Registrar": who.registrar,
                "Creation Date": who.creation_date,
                "Expiration Date": who.expiration_date,
                "Name Servers": who.name_servers
            }
        }