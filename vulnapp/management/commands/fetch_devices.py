import os
import requests
import json
import subprocess
from vulnapp import secrets

def fetch_auth_token():
    url = f"https://login.microsoftonline.com/{os.environ['MICROSOFT_TENANT_ID']}/oauth2/v2.0/token"
    payload = {
        "client_id": os.environ["MICROSOFT_CLIENT_ID"],
        "scope": "https://management.azure.com/.default",
        "client_secret": os.environ["MICROSOFT_CLIENT_SECRET"],
        "grant_type": "client_credentials"
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    response = requests.post(url, data=payload, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        return data["access_token"]
    else:
        raise Exception("Failed to fetch authentication token")

def fetch_devices_from_defender():
    token = fetch_auth_token()
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }
    url = "https://api.securitycenter.microsoft.com/api/machines"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()["value"]
    else:
        raise Exception(f"Failed to fetch devices: {response.status_code}")

def fetch_azure_vms():
    # Assuming Azure CLI is configured with a service principal or appropriate authentication
    result = subprocess.run(["az", "graph", "query", "-q", "Resources | where type =~ 'microsoft.compute/virtualmachines' | project id, name, resourceGroup, subscriptionId", "--output", "json"], stdout=subprocess.PIPE)
    vms = json.loads(result.stdout)
    return vms

def match_devices_and_vms(devices, vms):
    matched_devices = []
    for device in devices:
        for vm in vms:
            if device['computerName'].lower() == vm['name'].lower():
                matched_devices.append({
                    "device_name": device['computerName'],
                    "resource_group": vm['resourceGroup'],
                    "subscription_id": vm['subscriptionId'],
                    "vm_id": vm['id']
                })
    return matched_devices

def main():
    devices = fetch_devices_from_defender()
    vms = fetch_azure_vms()
    matched_devices = match_devices_and_vms(devices, vms)
    
    for matched in matched_devices:
        print(f"Device: {matched['device_name']} is in Resource Group: {matched['resource_group']} under Subscription: {matched['subscription_id']}")

if __name__ == "__main__":
    main()
