from django.core.management.base import BaseCommand
from django.db.models import Count
from vulnapp.models import Subscription, Device, MachineReference, ResourceGroup

class Command(BaseCommand):
    help = 'Populates the vulnerability count field for subscriptions and resource groups'

    def handle(self, *args, **kwargs):
        # Initialize dictionaries to store aggregated counts
        subscription_vuln_counts = {}
        resource_group_vuln_counts = {}

        # Fetch all devices
        devices = Device.objects.all()

        for device in devices:
            subscription = device.subscription
            resource_group = device.resource_group

            # Initialize vulnerability count dictionaries if not already present
            if subscription and subscription.pk not in subscription_vuln_counts:
                subscription_vuln_counts[subscription.pk] = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}

            if resource_group and resource_group.pk not in resource_group_vuln_counts:
                resource_group_vuln_counts[resource_group.pk] = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}

            # Fetch vulnerabilities for the device
            machine_references = MachineReference.objects.filter(device=device)

            for machine_ref in machine_references:
                severity = machine_ref.vulnerability.severity
                # Increment counts based on severity
                if subscription:
                    subscription_vuln_counts[subscription.pk][severity] += 1

                if resource_group:
                    resource_group_vuln_counts[resource_group.pk][severity] += 1

        # Update each subscription's vulnerability count
        for sub_id, counts in subscription_vuln_counts.items():
            Subscription.objects.filter(pk=sub_id).update(vulnerability_count=counts)
            self.stdout.write(self.style.SUCCESS(f'Successfully updated Subscription {sub_id} with vulnerability counts {counts}'))

        # Update each resource group's vulnerability count
        for rg_id, counts in resource_group_vuln_counts.items():
            ResourceGroup.objects.filter(pk=rg_id).update(vulnerability_count=counts)
            self.stdout.write(self.style.SUCCESS(f'Successfully updated Resource Group {rg_id} with vulnerability counts {counts}'))