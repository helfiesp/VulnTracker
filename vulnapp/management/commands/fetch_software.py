from django.core.management.base import BaseCommand, CommandError
import requests
import os
from vulnapp.models import Software, ScanStatus
from vulnapp import secrets

class Command(BaseCommand):
    help = 'Imports software data from Microsoft Security Center API'

    def handle(self, *args, **options):
        scan_status = ScanStatus.objects.create(scan_type='Microsoft Software Overview', status='in_progress', details='{}')

        def fetch_auth_token():
            url = "https://login.microsoftonline.com/{}/oauth2/v2.0/token".format(os.environ["MICROSOFT_TENANT_ID"])
            payload = {
                "client_id": os.environ["MICROSOFT_CLIENT_ID"],
                "scope": "https://api.securitycenter.microsoft.com/.default",
                "client_secret": os.environ["MICROSOFT_CLIENT_SECRET"],
                "grant_type": "client_credentials"
            }
            headers = {
                "Content-Type": "application/x-www-form-urlencoded"
            }
            response = requests.post(url, data=payload, headers=headers)

            if response.status_code == 200:
                data = response.json()
                return data["access_token"]
            else:
                raise CommandError('Failed to fetch authentication token.')

        try:
            BEARER_TOKEN = fetch_auth_token()
            headers = {
                'Authorization': f'Bearer {BEARER_TOKEN}',
                'Content-Type': 'application/json'
            }
            
            url = "https://api.securitycenter.microsoft.com/api/Software"  # Adjusted to fetch software data
            response = requests.get(url, headers=headers)

            if response.status_code == 200:
                software_data = response.json()
                for software in software_data["value"]:
                    software_obj, created = Software.objects.update_or_create(
                        id=software['id'],
                        defaults={
                            'name': software['name'],
                            'vendor': software['vendor'],
                            'weaknesses': software['weaknesses'],
                            'public_exploit': software['publicExploit'],
                            'active_alert': software['activeAlert'],
                            'exposed_machines': software['exposedMachines'],
                            'impact_score': software['impactScore'],
                        }
                    )
                    self.stdout.write(self.style.SUCCESS(f"{'Created' if created else 'Updated'}: {software_obj.name}"))
                
                scan_status.status = 'success'
                scan_status.details = '{"imported_count": %s}' % len(software_data["value"])
                scan_status.save()
            else:
                self.stdout.write(self.style.ERROR(f"Failed to fetch data: {response.status_code}"))
                scan_status.status = 'error'
                scan_status.error_message = f"HTTP Error {response.status_code}"
                scan_status.save()

        except Exception as e:
            scan_status.status = 'error'
            scan_status.error_message = str(e)
            scan_status.save()
            raise CommandError(f'An error occurred: {str(e)}')
