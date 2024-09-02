from django.core.management.base import BaseCommand
from django.db.models import Count
from vulnapp.models import Subscription, Device, MachineReference, ResourceGroup

class Command(BaseCommand):
    help = 'Populates the vulnerability count field for subscriptions and resource groups'

    def handle(self, *args, **kwargs):
        # Initialize today's date to filter recent data
        subscriptions = Subscription.objects.all()
        resource_groups = ResourceGroup.objects.all()

        # Iterate over all subscriptions
        for subscription in subscriptions:
            # Initialize vulnerability count dictionary
            subscription_vuln_count = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}

            # Fetch all devices related to the subscription
            devices = Device.objects.filter(subscription=subscription)

            for device in devices:
                # Fetch all vulnerabilities related to the device
                machine_references = MachineReference.objects.filter(device=device)

                for machine_ref in machine_references:
                    severity = machine_ref.vulnerability.severity
                    if severity in subscription_vuln_count:
                        subscription_vuln_count[severity] += 1
                    else:
                        subscription_vuln_count[severity] = 1

            # Update the subscription's vulnerability count
            subscription.vulnerability_count = subscription_vuln_count
            subscription.save()
            if subscription_vuln_count:
                self.stdout.write(self.style.SUCCESS(f'Successfully updated Subscription {subscription.display_name} with vulnerability counts {subscription_vuln_count}'))

        # Iterate over all resource groups
        for resource_group in resource_groups:
            # Initialize vulnerability count dictionary
            resource_group_vuln_count = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}

            # Fetch all devices related to the resource group
            devices = Device.objects.filter(resource_group=resource_group)

            for device in devices:
                # Fetch all vulnerabilities related to the device
                machine_references = MachineReference.objects.filter(device=device)

                for machine_ref in machine_references:
                    severity = machine_ref.vulnerability.severity
                    if severity in resource_group_vuln_count:
                        resource_group_vuln_count[severity] += 1
                    else:
                        resource_group_vuln_count[severity] = 1

            # Update the resource group's vulnerability count
            resource_group.vulnerability_count = resource_group_vuln_count
            resource_group.save()
            if resource_group_vuln_count:
                self.stdout.write(self.style.SUCCESS(f'Successfully updated Resource Group {resource_group.name} with vulnerability counts {resource_group_vuln_count}'))
