from django.core.management.base import BaseCommand, CommandError
import requests
from vulnapp.models import Software, SoftwareHosts, ScanStatus
from vulnapp import secrets
import os
from django.db.models import Case, When

from django.db import transaction
from requests.exceptions import RequestException
from urllib.parse import quote  # Import the quote function
import time

## DEPLETED METHOD, NOT IN USE ### 
class Command(BaseCommand):
    help = 'Fetches machine references for each software from Microsoft Security Center API'

    def fetch_auth_token(self):
        url = "https://login.microsoftonline.com/{}/oauth2/v2.0/token".format(os.environ["MICROSOFT_TENANT_ID"])
        payload = {
            "client_id": os.environ["MICROSOFT_CLIENT_ID"],
            "scope": "https://api.securitycenter.microsoft.com/.default",
            "client_secret": os.environ["MICROSOFT_CLIENT_SECRET"],
            "grant_type": "client_credentials"
        }
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        response = requests.post(url, data=payload, headers=headers)
        if response.status_code == 200:
            data = response.json()
            return data["access_token"]
        else:
            raise CommandError('Failed to fetch authentication token.')

    def fetch_machine_references(self, software_id, headers):
        encoded_software_id = quote(software_id, safe='')
        url = f"https://api.securitycenter.microsoft.com/api/Software/{encoded_software_id}/machineReferences"
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                return response.json()["value"]
            elif response.status_code == 429:
                self.stdout.write(self.style.WARNING(f"Rate limit exceeded for software ID {software_id}, retrying later."))
                time.sleep(300)  # Adjust based on API guidelines
                return "retry"
            elif response.status_code == 401:
                self.stdout.write(self.style.ERROR(f"Unauthorized access for software ID {software_id}. Token may have expired."))
                return "refresh_token"
            else:
                self.stdout.write(self.style.ERROR(f"Failed to fetch machine data for software ID {software_id}: {response.status_code}"))
                return []
        except RequestException as e:
            self.stdout.write(self.style.ERROR(f"Error fetching machine data for software ID {software_id}: {e}"))
            time.sleep(10)  # Adjust based on retry logic or API guidelines
            return []


    def handle(self, *args, **options):
        scan_status = ScanStatus.objects.create(scan_type='Microsoft Machine Software', status='in_progress', details='{}')

        try:
            BEARER_TOKEN = self.fetch_auth_token()
            headers = {'Authorization': f'Bearer {BEARER_TOKEN}', 'Content-Type': 'application/json'}

            software_entries = Software.objects.all()

            for software in software_entries:
                retries = 3
                while retries > 0:
                    machine_references_data = self.fetch_machine_references(software.id, headers)

                    if machine_references_data == "refresh_token":
                        # Refresh the token
                        BEARER_TOKEN = self.fetch_auth_token()
                        headers['Authorization'] = f'Bearer {BEARER_TOKEN}'
                        # No need to decrement retries here as we're handling a known issue (token expiration) rather than an unexpected error
                        continue  # Attempt to fetch the data again with the new token

                    elif machine_references_data == "retry":
                        # Handle rate limit or other retry scenario
                        retries -= 1
                        time.sleep(60)  # Sleep before retrying
                        continue

                    elif machine_references_data is not None:
                        # Successfully fetched data, break out of the retry loop
                        break
                    else:
                        # Unknown error, reduce retries
                        retries -= 1

                # Proceed with processing if machine_references_data is successfully fetched
                if machine_references_data is not None:
                    existing_hosts = {host.host_id: host for host in SoftwareHosts.objects.filter(software=software)}
                    new_hosts = []
                    update_hosts = []

                    for machine_data in machine_references_data:
                        if machine_data['computerDnsName'].startswith(("ws", "ia")) or "Android" in machine_data['osPlatform'] or "macOS" in machine_data['osPlatform']:
                            continue  # Skip the current loop iteration based on conditions

                        host_id = machine_data['id']
                        defaults = {
                            'software': software,
                            'host_id': host_id,
                            'computer_dns_name': machine_data['computerDnsName'],
                            'os_platform': machine_data['osPlatform'],
                            'rbac_group_name': machine_data.get('rbacGroupName', ''),
                        }

                        if host_id in existing_hosts:
                            for attr, value in defaults.items():
                                setattr(existing_hosts[host_id], attr, value)
                            update_hosts.append(existing_hosts[host_id])
                        else:
                            new_hosts.append(SoftwareHosts(**defaults))

                    if new_hosts:
                        SoftwareHosts.objects.bulk_create(new_hosts)
                    if update_hosts:
                        SoftwareHosts.objects.bulk_update(update_hosts, ['computer_dns_name', 'os_platform', 'rbac_group_name'])
                    if len(new_hosts) > 0:
                        self.stdout.write(self.style.SUCCESS(f"Processed {len(new_hosts)} new hosts machine references for software {software.name}."))
                    elif len(update_hosts) > 0:
                        self.stdout.write(self.style.SUCCESS(f"Processed {len(update_hosts)} update hosts machine references for software {software.name}."))
                else:
                    # If we exit the loop without fetching data, log an error
                    self.stdout.write(self.style.ERROR(f"Failed to process software ID {software.id} after retries."))
            time.sleep(2.5)
            scan_status.status = 'success'
            scan_status.save()

        except Exception as e:
            scan_status.status = 'error'
            scan_status.error_message = str(e)
            scan_status.save()
            self.stdout.write(self.style.ERROR(f'An error occurred during the scan: {str(e)}'))