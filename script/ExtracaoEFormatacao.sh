#!/usr/bin/env python3
import json
import requests
import datetime

WAZUH_API_URL = "https://localhost:55000"
WAZUH_USER = "wazuh_api_user"
WAZUH_PASSWORD = "your_password"
BLACKLIST_FILE = "/var/www/html/ipv6_blacklist.txt"

def get_wazuh_token(api_url, username, password):
auth_url = f"{api_url}/security/user/authenticate"
headers = {"Content-Type": "application/json"}
data = {"username": username, "password": password}
response = requests.post(auth_url, headers=headers, json=data, verify=False) # verify=False para testes, usar certificado em produção
response.raise_for_status()
return response.json()["data"]["token"]

def get_malicious_ips(api_url, token):
headers = {"Authorization": f"Bearer {token}"}
# Consulta alertas dos últimos 5 minutos com grupo 'blacklist'
end_time = datetime.datetime.now()
start_time = end_time - datetime.timedelta(minutes=5)
query = f"group=blacklist&from={start_time.strftime('%Y-%m-%dT%H:%M:%S')}&to={end_time.strftime('%Y-%m-%dT%H:%M:%S')}"
alerts_url = f"{api_url}/alerts?pretty=true&limit=1000&q={query}"
response = requests.get(alerts_url, headers=headers, verify=False)
response.raise_for_status()
alerts = response.json()["data"]["affected_items"]

malicious_ips = set()
for alert in alerts:
    if 'data' in alert and 'src_ip' in alert['data']:
        malicious_ips.add(alert['data']['src_ip'])
return list(malicious_ips)

def update_blacklist_file(ips, filename):
with open(filename, "w") as f:
for ip in ips:
f.write(f"{ip}\n")
print(f"Blacklist updated with {len(ips)} IPs.")

if name == "main":
try:
token = get_wazuh_token(WAZUH_API_URL, WAZUH_USER, WAZUH_PASSWORD)
ips = get_malicious_ips(WAZUH_API_URL, token)
update_blacklist_file(ips, BLACKLIST_FILE)
except Exception as e:
print(f"Error: {e}")