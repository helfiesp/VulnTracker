import os
import json
import requests
from django.core.management.base import BaseCommand, CommandError
from vulnapp.models import Device, Subscription, ResourceGroup, ScanStatus
from django.db import transaction
from vulnapp import secrets

class Command(BaseCommand):
    help = 'Fetches all virtual machines within each subscription and resource group and stores them in the Device model'

    def fetch_auth_token(self):
        """Fetches the Azure authentication token."""
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
            raise CommandError('Failed to fetch authentication token.')

    def fetch_vms_in_resource_group(self, subscription_id, resource_group_name, headers):
        """Fetches all VMs in a specific resource group."""
        url = f"https://management.azure.com/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}/providers/Microsoft.Compute/virtualMachines?api-version=2022-12-01"
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            return response.json().get("value", [])
        else:
            self.stdout.write(self.style.ERROR(f"Failed to fetch VMs for resource group {resource_group_name} in subscription {subscription_id}: {response.status_code}"))
            return []

    def handle(self, *args, **options):
        """Main method to handle fetching and storing device details."""
        scan_status = ScanStatus.objects.create(scan_type='Azure Device Fetch', status='in_progress', details='{}')

        try:
            # Fetch the Azure authentication token
            BEARER_TOKEN = self.fetch_auth_token()
            headers = {
                'Authorization': f'Bearer {BEARER_TOKEN}',
                'Content-Type': 'application/json'
            }

            # Fetch all subscriptions
            subscriptions = Subscription.objects.all()
            self.stdout.write(f"Found {subscriptions.count()} subscriptions to process.")

            for subscription in subscriptions:
                # Fetch all resource groups within the subscription
                resource_groups = ResourceGroup.objects.filter(subscription_id=subscription.subscription_id)
                self.stdout.write(f"Processing {resource_groups.count()} resource groups in subscription {subscription.subscription_id} ({subscription.display_name})")

                for resource_group in resource_groups:
                    # Fetch all VMs in the resource group
                    vms = self.fetch_vms_in_resource_group(subscription.subscription_id, resource_group.name, headers)

                    to_create = []

                    for vm in vms:
                        vm_id = vm['id']
                        vm_name = vm['name']
                        os_type = vm['properties']['storageProfile']['osDisk']['osType'] if 'osDisk' in vm['properties']['storageProfile'] else None

                        # Create or update Device record
                        to_create.append(Device(
                            device_id=vm_id,
                            display_name=vm_name,
                            operating_system=os_type,
                            device_type='Virtual Machine',  # Assuming all are VMs
                            subscription=subscription,
                            resource_group=resource_group,
                        ))

                    with transaction.atomic():
                        Device.objects.bulk_create(to_create, ignore_conflicts=True)
                        self.stdout.write(self.style.SUCCESS(f"Processed {len(to_create)} devices in resource group {resource_group.name}."))

            # Update scan status on success
            scan_status.status = 'success'
            scan_status.save()

        except Exception as e:
            scan_status.status = 'error'
            scan_status.error_message = str(e)
            scan_status.save()
            raise CommandError(f'An error occurred: {str(e)}')
