import requests
import json
import urllib3

# Ignore SSL warnings (remove in production)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PRIMARY_SERVER = "nbu-master.example.com"
API_KEY = "YOUR_API_KEY"
POLICY_NAME = "Oracle_PROD"

headers = {
    "Authorization": API_KEY,
    "Accept": "application/vnd.netbackup+json;version=3.0",
    "Content-Type": "application/vnd.netbackup+json;version=3.0"
}

url = f"https://{PRIMARY_SERVER}:1556/netbackup/config/policies/{POLICY_NAME}"

response = requests.get(
    url,
    headers=headers,
    verify=False
)

response.raise_for_status()

with open(f"{POLICY_NAME}.json", "w", encoding="utf-8") as f:
    json.dump(response.json(), f, indent=4)

print(f"Policy '{POLICY_NAME}' saved as {POLICY_NAME}.json")
