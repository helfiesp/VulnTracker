import os
import json
import requests
from django.core.management.base import BaseCommand, CommandError
from vulnapp.models import ResourceGroup, ScanStatus
from vulnapp import secrets

class Command(BaseCommand):
    help = 'Imports resource group data from Azure Management API'

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
        scan_status = ScanStatus.objects.create(scan_type='Azure_ResourceGroup_Import', status='in_progress', details='{}')
        try:
            BEARER_TOKEN = self.fetch_auth_token()
            headers = {
                'Authorization': f'Bearer {BEARER_TOKEN}',
                'Content-Type': 'application/json'
            }

            # Fetch all subscriptions first
            subscriptions_url = "https://management.azure.com/subscriptions?api-version=2022-12-01"
            subscriptions_response = requests.get(subscriptions_url, headers=headers)
            if subscriptions_response.status_code != 200:
                raise CommandError(f"Failed to fetch subscriptions: {subscriptions_response.status_code}")

            subscriptions = subscriptions_response.json()["value"]
            processed_count = 0

            # Iterate over each subscription to fetch resource groups
            for subscription in subscriptions:
                subscription_id = subscription['subscriptionId']
                base_url = f"https://management.azure.com/subscriptions/{subscription_id}/resourcegroups"
                api_version = "2022-12-01"
                url = f"{base_url}?api-version={api_version}"
                
                response = requests.get(url, headers=headers)

                if response.status_code == 200:
                    resource_groups = response.json()["value"]
                    for rg_data in resource_groups:
                        processed_count += 1
                        ResourceGroup.objects.update_or_create(
                            resource_group_id=rg_data['id'],
                            defaults={
                                'subscription_id': subscription_id,
                                'name': rg_data['name'],
                                'location': rg_data['location'],
                                'managed_by': rg_data.get('managedBy'),
                                'provisioning_state': rg_data.get('properties', {}).get('provisioningState'),
                            }
                        )
                        print(f"Processed resource group: {rg_data['name']} (ID: {rg_data['id']})")

                else:
                    raise CommandError(f"Failed to fetch resource groups for subscription {subscription_id}: {response.status_code}")

            # Update scan status on success
            scan_status.status = 'success'
            scan_status.details = json.dumps({"processed_resource_groups": processed_count})
            scan_status.save()
            self.stdout.write(self.style.SUCCESS(f"Successfully processed {processed_count} resource groups."))
        
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'An error occurred: {str(e)}'))
            scan_status.status = 'error'
            scan_status.error_message = str(e)
            scan_status.save()
