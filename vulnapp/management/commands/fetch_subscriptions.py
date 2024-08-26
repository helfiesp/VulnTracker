import os
import json
import requests
from dateutil.parser import parse
from django.core.management.base import BaseCommand, CommandError
from vulnapp.models import Subscription, ScanStatus
from vulnapp import secrets

class Command(BaseCommand):
    help = 'Imports subscription data from Azure Management API'

    def fetch_auth_token(self):
        url = "https://login.microsoftonline.com/{}/oauth2/v2.0/token".format(os.environ["MICROSOFT_TENANT_ID"])
        payload = {
            "client_id": os.environ["MICROSOFT_CLIENT_ID"],
            "scope": "https://management.azure.com/.default",
            "client_secret": os.environ["MICROSOFT_CLIENT_SECRET"],
            "grant_type": "client_credentials"
        }
        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }
        response = requests.post(url, data=payload, headers=headers)
        
        if response.status_code == 200:
            print("Fetched auth token.")
            data = response.json()
            return data["access_token"]
        else:
            raise CommandError('Failed to fetch authentication token.')

    def handle(self, *args, **options):
        scan_status = ScanStatus.objects.create(scan_type='Azure_Subscription_Import', status='in_progress', details='{}')
        try:
            BEARER_TOKEN = self.fetch_auth_token()
            headers = {
                'Authorization': f'Bearer {BEARER_TOKEN}',
                'Content-Type': 'application/json'
            }
            base_url = "https://management.azure.com/subscriptions"
            api_version = "2022-12-01"
            url = f"{base_url}?api-version={api_version}"
            
            response = requests.get(url, headers=headers)

            if response.status_code == 200:
                subscriptions = response.json()
                print(subscriptions)
                processed_count = 0
                for sub_data in subscriptions:
                    processed_count += 1
                    Subscription.objects.update_or_create(
                        subscription_id=sub_data['subscriptionId'],
                        defaults={
                            'display_name': sub_data['displayName'],
                            'state': sub_data['state'],
                            'tenant_id': sub_data.get('tenantId'),
                        }
                    )
                    print(f"Processed subscription: {sub_data['displayName']} (ID: {sub_data['subscriptionId']})")

                # Update scan status on success
                scan_status.status = 'success'
                scan_status.details = json.dumps({"processed_subscriptions": processed_count})
                scan_status.save()
                self.stdout.write(self.style.SUCCESS(f"Successfully processed {processed_count} subscriptions."))
            else:
                raise CommandError(f"Failed to fetch data: {response.status_code}")

        except Exception as e:
            self.stdout.write(self.style.ERROR(f'An error occurred: {str(e)}'))
            scan_status.status = 'error'
            scan_status.error_message = str(e)
            scan_status.save()
