from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from urllib.parse import quote
import os
import requests
import time
from dateutil.parser import parse
from vulnapp.models import ScanStatus, Vulnerability, MachineReference, Device
from vulnapp import secrets

class Command(BaseCommand):
    help = 'Imports device data from Entra ID'

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
            "scope": "https://graph.microsoft.com/.default",
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

    def fetch_devices(self, headers):
        url = f"https://graph.microsoft.com/v1.0/devices"
        try:
            response = requests.get(url, headers=headers)

            if response.status_code == 200:
                return response.json()["value"]
            elif response.status_code == 429:
                self.stdout.write(self.style.WARNING("Rate limit exceeded, retrying later."))
                return "retry"
            elif response.status_code == 401:
                self.stdout.write(self.style.ERROR("Unauthorized access. Token may have expired."))
                return "refresh_token"
            else:
                self.stdout.write(self.style.ERROR(f"Unexpected response: {response.status_code} - {response.text}"))
                return []
        except requests.RequestException as e:
            self.stdout.write(self.style.ERROR(f"Error fetching data: {e}"))
            return []

    def process_devices(self, devices, headers):
        devices_to_retry = []
        for device_data in devices:
            time.sleep(1)  # Throttle requests to avoid rate limits
            retry_count = 0
            while retry_count < 3:  # Allow up to 3 retries
                if device_data == "retry":
                    self.stdout.write(self.style.WARNING("Retrying..."))
                    retry_count += 1
                    time.sleep(300)  # Wait for 5 minutes before retrying
                    continue

                if device_data == "refresh_token":
                    new_token = self.refresh_auth_token()
                    if new_token:
                        headers['Authorization'] = f'Bearer {new_token}'
                        continue  # Retry with the new token
                    else:
                        break  # Exit the loop if token refresh failed

                if not device_data:
                    break

                with transaction.atomic():
                    device, created = Device.objects.update_or_create(
                        device_id=device_data['id'],
                        defaults={
                            'display_name': device_data.get('displayName'),
                            'operating_system': device_data.get('operatingSystem'),
                            'operating_system_version': device_data.get('operatingSystemVersion'),
                            'device_type': device_data.get('deviceType'),
                            'last_sync_date_time': parse(device_data.get('approximateLastSignInDateTime')) if device_data.get('approximateLastSignInDateTime') else None,
                            'compliance_state': device_data.get('complianceState'),
                            'is_managed': device_data.get('isManaged'),
                            'is_compliant': device_data.get('isCompliant'),
                        }
                    )

                    # You can add logic here to associate vulnerabilities if needed
                    self.stdout.write(self.style.SUCCESS(f"Processed device {device.device_id}"))
                    break

            if retry_count == 3:
                devices_to_retry.append(device_data)

        return devices_to_retry

    def handle(self, *args, **options):
        scan_status = ScanStatus.objects.create(scan_type='Entra ID Device Import', status='in_progress', details='{}')
        try:
            BEARER_TOKEN = self.fetch_auth_token()
            headers = {
                'Authorization': f'Bearer {BEARER_TOKEN}',
                'Content-Type': 'application/json'
            }
            
            devices = self.fetch_devices(headers)

            devices_to_retry = self.process_devices(devices, headers)

            while devices_to_retry:
                self.stdout.write(self.style.WARNING("Retrying for devices that failed in the first round..."))
                devices_to_retry = self.process_devices(devices_to_retry, headers)

            scan_status.status = 'success'
            scan_status.details = '{}'
            scan_status.save()

        except Exception as e:
            scan_status.status = 'error'
            scan_status.error_message = str(e)
            scan_status.save()
            raise CommandError(f'An error occurred: {str(e)}")