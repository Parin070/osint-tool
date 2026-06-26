from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

def display_ip_results(results):
    print("IP Report\n")

    #AbuseIPDB
    table_ab = Table(title="AbuseIPDB")
    table_ab.add_column("Field", justify="center", style="cyan")
    table_ab.add_column("Value", justify="center", style="magenta")

    table_ab.add_row("Abuse Score", str(results["AbuseIPDB"]["data"]["abuseConfidenceScore"]))
    table_ab.add_row("Total Reports", str(results["AbuseIPDB"]["data"]["totalReports"]))
    table_ab.add_row("Distinct Users", str(results["AbuseIPDB"]["data"]["numDistinctUsers"]))
    table_ab.add_row("Tor Exit Node", str(results["AbuseIPDB"]["data"]["isTor"]))
    table_ab.add_row("Last Reported", str(results["AbuseIPDB"]["data"]["lastReportedAt"]))

    console.print(table_ab)

    print()

    #Shodan
    table_sh = Table(title="Shodan")
    table_sh.add_column("Field", justify="center", style="cyan")
    table_sh.add_column("Value", justify="center", style="magenta")

    table_sh.add_row("Organization", str(results["Shodan"]["org"]))
    table_sh.add_row("ISP", str(results["Shodan"]["isp"]))
    location = f"{results['Shodan']['city']}, {results['Shodan']['country_name']}"
    table_sh.add_row("Location", location)
    table_sh.add_row("ASN", str(results["Shodan"]["asn"]))
    table_sh.add_row("Ports", str(results["Shodan"]["ports"]))
    table_sh.add_row("Hostnames", str(results["Shodan"]["hostnames"]))
    table_sh.add_row("CVEs", str(results["Shodan"].get("vulns", "None Found")))

    console.print(table_sh)

    print()

    #VirusTotal - Add range for values
    table_vt = Table(title="VirusTotal")
    table_vt.add_column("Field", justify="center", style="cyan")
    table_vt.add_column("Value", justify="center", style="magenta")

    vt = results["VirusTotal"]["data"]["attributes"]
    table_vt.add_row("Malicious", str(vt["last_analysis_stats"]["malicious"]))
    table_vt.add_row("Harmless", str(vt["last_analysis_stats"]["harmless"]))
    table_vt.add_row("Suspicious", str(vt["last_analysis_stats"]["suspicious"]))
    table_vt.add_row("Reputation", str(vt["reputation"]))
    table_vt.add_row("AS Owner", vt["as_owner"])

    console.print(table_vt)

    print()

    # Risk Score
    table_rs = Table(title="Risk Score")
    table_rs.add_column("Field", justify="center", style="cyan")
    table_rs.add_column("Value", justify="center", style="magenta")

    table_rs.add_row("Risk Score", str(results["risk_score"]))

    console.print(table_rs)

def display_domain_results(results):
    print("Domain Report")

    #Whois
    table_wh = Table(title="Whois")
    table_wh.add_column("Field", justify="center", style="cyan")
    table_wh.add_column("Value", justify="center", style="magenta")

    table_wh.add_row("Registrar", str(results["Whois"]["Registrar"]))
    table_wh.add_row("Creation Date", str(results["Whois"]["Creation Date"]))
    table_wh.add_row("Expiration Date", str(results["Whois"]["Expiration Date"]))
    table_wh.add_row("Name Servers", str(results["Whois"]["Name Servers"]))

    console.print(table_wh)

    print()

    #DNS
    table_dns = Table(title="DNS")
    table_dns.add_column("Field", justify="center", style="cyan")
    table_dns.add_column("Value", justify="center", style="magenta")

    table_dns.add_row("A", "\n".join(results["DNS"]["A"]))
    table_dns.add_row("MX", "\n".join(results["DNS"]["MX"]))
    table_dns.add_row("TXT", "\n".join(results["DNS"]["TXT"]))

    console.print(table_dns)

    print()

    #crt.sh
    table_crt = Table(title="Subdomains")
    table_crt.add_column("Field", justify="center", style="cyan")

    for sub in results["Subdomains"]:
        table_crt.add_row(sub)

    console.print(table_crt)

    print()
    
    #VirusTotal
    table_vt = Table(title="VirusTotal")
    table_vt.add_column("Field", justify="center", style="cyan")
    table_vt.add_column("Value", justify="center", style="magenta")

    vt = results["VirusTotal"]["data"]["attributes"]
    table_vt.add_row("Malicious", str(vt["last_analysis_stats"]["malicious"]))
    table_vt.add_row("Harmless", str(vt["last_analysis_stats"]["harmless"]))
    table_vt.add_row("Suspicious", str(vt["last_analysis_stats"]["suspicious"]))
    table_vt.add_row("Reputation", str(vt["reputation"]))

    console.print(table_vt)

    print()

    # Risk Score
    table_rs = Table(title="Risk Score")
    table_rs.add_column("Field", justify="center", style="cyan")
    table_rs.add_column("Value", justify="center", style="magenta")

    table_rs.add_row("Risk Score", str(results["risk_score"]))

    console.print(table_rs)

def display_email_results(results):
    print("Email Report")
    if "error" in results:
        console.print(f"[red]{results['error']}[/red]")
        return
    
    #Hudson Rock
    table_hr = Table(title="Huson Rock")
    table_hr.add_column("Field", justify="center", style="cyan")
    table_hr.add_column("Value", justify="center", style="magenta")

    hr = results["Hudson Rock"]
    table_hr.add_row("Total User Services", str(hr.get("total_user_services", 0)))
    table_hr.add_row("Total Corporate Services", str(hr.get("total_corporate_services", 0)))
    table_hr.add_row("Infections Found", str(len(hr.get("stealers", []))))
    
    if hr.get("stealers"):
        latest = hr["stealers"][0]
        table_hr.add_row("Most Recent Infection", latest.get("date_compromised", "N/A"))
        table_hr.add_row("Computer Name", latest.get("computer_name", "N/A"))
        table_hr.add_row("OS", latest.get("operating_system", "N/A"))
    
    console.print(table_hr)

    print()

    # Risk Score
    table_rs = Table(title="Risk Score")
    table_rs.add_column("Field", justify="center", style="cyan")
    table_rs.add_column("Value", justify="center", style="magenta")

    table_rs.add_row("Risk Score", str(results["risk_score"]))

    console.print(table_rs)

def display_people_results(results):
    table = Table(title="Profiles")
    table.add_column("Profile URL", style="cyan")

    if "Sherlock" in results:
        data = results["Sherlock"]
        table.title = f"Sherlock — {data['Username']}"
        for profile in data["Profiles"]:
            table.add_row(profile)

    elif "NameDork" in results:
        data = results["NameDork"]
        table.title = f"Name Search — {data['Full Name']}"
        for profile in data["Profiles"]:
            table.add_row(profile)

    console.print(table)