import requests
import os

def summarize(results):
    response = requests.post(
        "https://openrouter.ai/api/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {os.getenv('OPENROUTER')}",
            "Content-Type": "application/json"
        },
        json={
            "model": "openrouter/free",
            "messages": [
                {
                    "role": "system",
                    "content": "You are a cybersecurity analyst. Analyze this OSINT data and provide a concise threat assessment."
                },
                {
                    "role": "user",
                    "content": f"Here is OSINT scan data: {results}. Summarize key findings, flag anything suspicious, give a risk verdict."
                }
            ]
        }
    )
    return response.json()