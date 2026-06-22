import requests
import os

def summarize(results):
    response = requests.post(
        "https://openrouter.ai/api/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {os.getenv('OPENROUTER')}",
            "Content-Type": "application/json"
        }
    )