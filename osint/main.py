from rich.console import Console
from rich.text import Text
from rich.panel import Panel
from dotenv import load_dotenv
from .modules.ip import IPRecon
from .modules.domain import DomainRecon
from .output.terminal import display_ip_results
from .output.terminal import display_domain_results

console = Console()
ASCII_ART = """
 ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗███╗   ███╗ █████╗ ██████╗ 
██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝████╗ ████║██╔══██╗██╔══██╗
██║  ███╗███████║██║   ██║███████╗   ██║   ██╔████╔██║███████║██████╔╝
██║   ██║██╔══██║██║   ██║╚════██║   ██║   ██║╚██╔╝██║██╔══██║██╔═══╝ 
╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   ██║ ╚═╝ ██║██║  ██║██║     
 ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     
"""

load_dotenv()

def main():
    console.print(Panel.fit(ASCII_ART, style = "bold cyan", title="[magenta]GhostMap v0.1[/magenta]", subtitle="[magenta]OSINT Recon Tool[/magenta]"))
    while True:
        console.print("\nWhat do you want to recon?", style="bold magenta")
        console.print("1. IP\n2. Domain\n3. Email\n0. Exit\n", style="bold magenta")

        choice = (input("Enter your choice: "))
        if choice == "1":
            target = input("Enter IP: ")
            print(f"Running IP recon on {target}")
            recon = IPRecon(target)
            recon.run()
            display_ip_results(recon.results)
        elif choice == "2":
            target = input("Enter domain: ")
            print(f"Running domain recon on {target}")
            recon = DomainRecon(target)
            recon.run()
            display_domain_results(recon.results)
        elif choice == "3":
            target = input("Enter email: ")
            print(f"Running email recon on {target}")
        elif choice == "0":
            print("Exiting...")
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()