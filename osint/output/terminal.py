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

