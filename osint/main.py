from rich import print
import requests
import typer

response = requests.get("https://api.github.com")
print(response.json())

app = typer.Typer()

@app.command()
def scan(ip: str = None, domain: str = None, email: str = None):
    if ip:
        print(f"Scanning IP: {ip}")
    if domain:
        print(f"Scanning domain: {domain}")
    if email:
        print(f"Scanning email: {email}")

if __name__ == "__main__":
    app()