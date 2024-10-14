from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from urllib.parse import quote
import os
import requests
import time
from dateutil.parser import parse
from vulnapp.models import ScanStatus, Vulnerability, MachineReference
from vulnapp import secrets

class Command(BaseCommand):
    help = 'Imports machine reference data for vulnerabilities from Microsoft Security Center API'

    def refresh_auth_token(self):
        try:
            return self.fetch_auth_token()
        except CommandError as e:
            self.stdout.write(self.style.ERROR(f"Failed to refresh token: {str(e)}"))
            return None

    def fetch_auth_token(self):
        url = f"https://login.microsoftonline.com/{os.environ['MICROSOFT_TENANT_ID']}/oauth2/v2.0/token"
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

    def fetch_machine_references(self, vulnerability_id, headers):
        url = f"https://api-eu.securitycenter.microsoft.com/api/vulnerabilities/{vulnerability_id}/machineReferences"
        try:
            response = requests.get(url, headers=headers)

            if response.status_code == 200:
                return response.json()["value"]
            elif response.status_code == 429:
                self.stdout.write(f"DEBUG: API Response Status {response.status_code} for vulnerability {vulnerability_id}")  # Debug log
                self.stdout.write(self.style.WARNING("Rate limit exceeded, retrying later."))
                return "retry"
            elif response.status_code == 401:
                self.stdout.write(f"DEBUG: API Response Status {response.status_code} for vulnerability {vulnerability_id}")  # Debug log
                self.stdout.write(self.style.ERROR("Unauthorized access. Token may have expired."))
                return "refresh_token"
            else:
                self.stdout.write(f"DEBUG: API Response Status {response.status_code} for vulnerability {vulnerability_id}")  # Debug log
                self.stdout.write(self.style.ERROR(f"Unexpected response: {response.status_code} - {response.text}"))
                return []
        except requests.RequestException as e:
            self.stdout.write(self.style.ERROR(f"Error fetching data: {e}"))
            return []

    def process_vulnerabilities(self, vulnerabilities, headers):
        vulnerabilities_to_retry = []
        for vulnerability in vulnerabilities:
            time.sleep(2.5)
            retry_count = 0
            while retry_count < 3:  # Allow up to 3 retries
                machine_references_data = self.fetch_machine_references(vulnerability.id, headers)
                if machine_references_data == "retry":
                    self.stdout.write(self.style.WARNING(f"Retrying for vulnerability {vulnerability.id}..."))
                    retry_count += 1
                    time.sleep(300)  # Wait for 5 minutes before retrying
                    continue

                if machine_references_data == "refresh_token":
                    new_token = self.refresh_auth_token()
                    if new_token:
                        headers['Authorization'] = f'Bearer {new_token}'
                        continue  # Retry with the new token
                    else:
                        break  # Exit the loop if token refresh failed

                if not machine_references_data:
                    break

                seen_machine_ids = set()  # Track seen machine_ids to avoid duplicates
                to_create = []

                for machine_data in machine_references_data:
                    machine_id = machine_data['id']
                    if machine_id in seen_machine_ids:
                        continue
                    seen_machine_ids.add(machine_id)

                    to_create.append(MachineReference(
                        vulnerability=vulnerability,
                        machine_id=machine_id,
                        computer_dns_name=machine_data['computerDnsName'].replace(".psr.local", "").lower(),
                        os_platform=machine_data['osPlatform'],
                        rbac_group_name=machine_data.get('rbacGroupName', ''),
                        rbac_group_id=machine_data.get('rbacGroupId', 0),
                        detection_time=parse(machine_data.get('detectionTime')) if machine_data.get('detectionTime') else None,
                    ))

                with transaction.atomic():
                    MachineReference.objects.bulk_create(to_create)
                    self.stdout.write(self.style.SUCCESS(f"Processed {len(to_create)} machine references for vulnerability {vulnerability.id}"))
                    break

            if retry_count == 3:
                vulnerabilities_to_retry.append(vulnerability)

        return vulnerabilities_to_retry

    def handle(self, *args, **options):
        scan_status = ScanStatus.objects.create(scan_type='Microsoft Machine Vulnerabilities', status='in_progress', details='{}')
        try:
            BEARER_TOKEN = self.fetch_auth_token()
            headers = {
                'Authorization': f'Bearer {BEARER_TOKEN}',
                'Content-Type': 'application/json'
            }
            
            MachineReference.objects.all().delete()
            vulnerabilities = Vulnerability.objects.all()

            vulnerabilities_to_retry = self.process_vulnerabilities(vulnerabilities, headers)

            while vulnerabilities_to_retry:
                self.stdout.write(self.style.WARNING("Retrying for vulnerabilities that failed in the first round..."))
                vulnerabilities_to_retry = self.process_vulnerabilities(vulnerabilities_to_retry, headers)

            scan_status.status = 'success'
            scan_status.details = '{}'
            scan_status.save()

        except Exception as e:
            scan_status.status = 'error'
            scan_status.error_message = str(e)
            scan_status.save()
            raise CommandError(f'An error occurred: {str(e)}')
