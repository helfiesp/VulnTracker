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
        # Updated API version to a supported one
        api_version = "2023-09-01"  # Use a supported API version
        url = f"https://management.azure.com/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}/providers/Microsoft.Compute/virtualMachines?api-version={api_version}"
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            vms = response.json().get("value", [])
            if len(vms):
                self.stdout.write(self.style.SUCCESS(f"Found {len(vms)} VMs in resource group {resource_group_name} under subscription {subscription_id}."))
            return vms
        elif response.status_code == 404:
            return []  # Return an empty list if no VMs are found
        else:
            return []

    def fetch_network_interface_details(self, subscription_id, resource_group_name, vm_name, headers):
        """Fetches network interface details for a VM."""
        # Updated API version for NICs
        api_version = "2023-09-01"  # Use a supported API version
        url = f"https://management.azure.com/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}/providers/Microsoft.Network/networkInterfaces?api-version={api_version}"
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            network_interfaces = response.json().get("value", [])
            for nic in network_interfaces:
                # Check if NIC belongs to the VM
                if nic.get('virtualMachine', {}).get('id', '').lower() == vm_name.lower():
                    return nic  # Return the network interface details for the VM
        return None  # No network interface found

    def fetch_public_ip(self, subscription_id, resource_group_name, public_ip_id, headers):
        """Fetches details of the public IP address."""
        api_version = "2023-09-01"  # Use a supported API version
        url = f"https://management.azure.com{public_ip_id}?api-version={api_version}"
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            public_ip_details = response.json()
            return public_ip_details
        return None

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
                resource_groups = ResourceGroup.objects.filter(subscription=subscription)

                for resource_group in resource_groups:
                    # Fetch all VMs in the resource group
                    vms = self.fetch_vms_in_resource_group(subscription.subscription_id, resource_group.name, headers)

                    if not vms:
                        continue  # Skip to the next resource group if no VMs found

                    to_create = []
                    to_update = []

                    for vm in vms:
                        # Extracting VM details
                        vm_id = vm.get('id', None)
                        vm_name = vm.get('name', None).lower()
                        os_type = vm.get('properties', {}).get('storageProfile', {}).get('osDisk', {}).get('osType', None)
                        os_version = vm.get('properties', {}).get('osProfile', {}).get('windowsConfiguration', {}).get('additionalUnattendContent', [{}])[0].get('content', None)
                        compliance_state = vm.get('properties', {}).get('provisioningState', None)
                        last_sync = vm.get('properties', {}).get('instanceView', {}).get('statuses', [{}])[0].get('time', None)
                        
                        # Fetch network interface details
                        network_interface = self.fetch_network_interface_details(subscription.subscription_id, resource_group.name, vm_id, headers)

                        if network_interface:
                            public_ip_assigned = False  # Assume no public IP by default
                            # Iterate over the network interface's IP configurations
                            ip_configurations = network_interface.get('properties', {}).get('ipConfigurations', [])
                            
                            for ip_config in ip_configurations:
                                public_ip = ip_config.get('properties', {}).get('publicIPAddress', None)
                                if public_ip:
                                    public_ip_details = self.fetch_public_ip(subscription.subscription_id, resource_group.name, public_ip['id'], headers)
                                    if public_ip_details:
                                        public_ip_assigned = True  # VM is publicly exposed
                                        self.stdout.write(self.style.WARNING(f"VM {vm_name} is publicly exposed with IP: {public_ip_details['properties']['ipAddress']}"))

                        # Log or update the VM record with public exposure status
                        if public_ip_assigned:
                            # Save or update this information to your Device model
                            self.stdout.write(self.style.WARNING(f"VM {vm_name} is publicly accessible."))
                        else:
                            self.stdout.write(self.style.SUCCESS(f"VM {vm_name} is not publicly accessible."))

                        # Debug output to verify VM details
                        self.stdout.write(f"Processing VM: {vm_name}, ID: {vm_id}, OS: {os_type}, OS Version: {os_version}")

                        if not vm_id or not vm_name:
                            self.stdout.write(self.style.ERROR(f"VM details are incomplete: {vm}"))
                            continue  # Skip this VM if critical details are missing


                        # Check if the device already exists
                        device = Device.objects.filter(device_id=vm_id).first()
                        if device:
                            # If the device exists, update it
                            device.display_name = vm_name
                            device.operating_system = os_type
                            device.operating_system_version = os_version
                            device.compliance_state = compliance_state
                            device.last_sync_date_time = last_sync
                            device.subscription = subscription
                            device.resource_group = resource_group
                            to_update.append(device)
                        else:
                            # If the device does not exist, create a new entry
                            to_create.append(Device(
                                device_id=vm_id,
                                display_name=vm_name,
                                operating_system=os_type,
                                operating_system_version=os_version,
                                compliance_state=compliance_state,
                                last_sync_date_time=last_sync,
                                device_type='Virtual Machine',  # Assuming all are VMs
                                subscription=subscription,
                                resource_group=resource_group,
                            ))

                    # Bulk create and update devices
                    with transaction.atomic():
                        if to_create:
                            Device.objects.bulk_create(to_create, ignore_conflicts=True)
                            self.stdout.write(self.style.SUCCESS(f"Created {len(to_create)} new devices in resource group {resource_group.name}."))
                        if to_update:
                            Device.objects.bulk_update(to_update, fields=[
                                'display_name', 'operating_system', 'operating_system_version', 'compliance_state',
                                'last_sync_date_time', 'subscription', 'resource_group'
                            ])
                            self.stdout.write(self.style.SUCCESS(f"Updated {len(to_update)} existing devices in resource group {resource_group.name}."))

            # Update scan status on success
            scan_status.status = 'success'
            scan_status.save()

        except Exception as e:
            scan_status.status = 'error'
            scan_status.error_message = str(e)
            scan_status.save()
            raise CommandError(f'An error occurred: {str(e)}')