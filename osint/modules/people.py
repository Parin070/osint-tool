from .base import Recon
import subprocess

class PeopleRecon(Recon):
    def run(self):
        result = subprocess.run (["sherlock", self.target], capture_output=True, text=True)
        output = result.stdout

        found = []
        for line in output.split("\n"):
            if "[+]" in line:
                found.append(line.strip())

        self.results = {
            "Sherlock": {
                "Username": self.target,
                "Profiles": found
            }
        }