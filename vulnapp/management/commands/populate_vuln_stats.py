from django.core.management.base import BaseCommand
from django.db.models import Count
from django.utils import timezone
from vulnapp.models import Subscription, Device, MachineReference, ResourceGroup

class Command(BaseCommand):
    help = 'Populates the vulnerability count field for subscriptions and resource groups'

    def handle(self, *args, **kwargs):
        # Initialize dictionaries to store aggregated counts
        subscription_vuln_counts = {}
        resource_group_vuln_counts = {}

        # Fetch all subscriptions and resource groups
        subscriptions = Subscription.objects.all()
        resource_groups = ResourceGroup.objects.all()

        # Initialize today's date to filter recent data
        today = timezone.now().date()

        # Iterate over all devices for each subscription and resource group
        for subscription in subscriptions:
            # Initialize vulnerability count dictionary
            subscription_vuln_counts[subscription.pk] = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}

            # Fetch all devices related to the subscription
            devices = Device.objects.filter(subscription=subscription)

            for device in devices:
                # Fetch MachineReference objects for the current device
                vuln_data = MachineReference.objects.filter(device=device)

                # Fetch severity statistics for the vulnerabilities associated with this device
                severity_statistics = vuln_data.values('vulnerability__severity').annotate(total_count=Count('vulnerability__severity'))

                # Combine all entries of each severity level into a single dictionary element
                for entry in severity_statistics:
                    severity = entry['vulnerability__severity']
                    total_count = entry['total_count']
                    if severity in subscription_vuln_counts[subscription.pk]:
                        subscription_vuln_counts[subscription.pk][severity] += total_count
                    else:
                        subscription_vuln_counts[subscription.pk][severity] = total_count

            # Update the subscription's vulnerability count
            subscription.vulnerability_count = subscription_vuln_counts[subscription.pk]
            subscription.save()

            self.stdout.write(self.style.SUCCESS(f'Successfully updated Subscription {subscription.display_name} with vulnerability counts {subscription_vuln_counts[subscription.pk]}'))

        # Iterate over all devices for each resource group
        for resource_group in resource_groups:
            # Initialize vulnerability count dictionary
            resource_group_vuln_counts[resource_group.pk] = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}

            # Fetch all devices related to the resource group
            devices = Device.objects.filter(resource_group=resource_group)

            for device in devices:
                # Fetch MachineReference objects for the current device
                vuln_data = MachineReference.objects.filter(device=device)

                # Fetch severity statistics for the vulnerabilities associated with this device
                severity_statistics = vuln_data.values('vulnerability__severity').annotate(total_count=Count('vulnerability__severity'))

                # Combine all entries of each severity level into a single dictionary element
                for entry in severity_statistics:
                    severity = entry['vulnerability__severity']
                    total_count = entry['total_count']
                    if severity in resource_group_vuln_counts[resource_group.pk]:
                        resource_group_vuln_counts[resource_group.pk][severity] += total_count
                    else:
                        resource_group_vuln_counts[resource_group.pk][severity] = total_count

            # Update the resource group's vulnerability count
            resource_group.vulnerability_count = resource_group_vuln_counts[resource_group.pk]
            resource_group.save()

            self.stdout.write(self.style.SUCCESS(f'Successfully updated Resource Group {resource_group.name} with vulnerability counts {resource_group_vuln_counts[resource_group.pk]}'))
