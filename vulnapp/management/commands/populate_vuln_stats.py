from django.core.management.base import BaseCommand
from django.db.models import Count
from myapp.models import Subscription, Device, MachineReference, ResourceGroup

class Command(BaseCommand):
    help = 'Populates the vulnerability count field for subscriptions and resource groups'

    def handle(self, *args, **kwargs):
        # Update vulnerability counts for each subscription
        subscriptions = Subscription.objects.all()
        for subscription in subscriptions:
            # Get all devices for the subscription
            devices = Device.objects.filter(subscription=subscription)

            # Initialize the vulnerability count dictionary
            vulnerability_count = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}

            # Get the vulnerability counts grouped by severity
            machine_references = MachineReference.objects.filter(device__in=devices)
            severity_counts = machine_references.values('vulnerability__severity').annotate(count=Count('vulnerability__severity'))

            # Populate the vulnerability count dictionary
            for severity in severity_counts:
                severity_level = severity['vulnerability__severity']
                count = severity['count']
                if severity_level in vulnerability_count:
                    vulnerability_count[severity_level] = count

            # Update the subscription with the calculated vulnerability count
            subscription.vulnerability_count = vulnerability_count
            subscription.save()

            self.stdout.write(self.style.SUCCESS(f'Successfully updated {subscription} with vulnerability counts'))

        # Update vulnerability counts for each resource group
        resource_groups = ResourceGroup.objects.all()
        for resource_group in resource_groups:
            # Get all devices for the resource group
            devices = Device.objects.filter(resource_group=resource_group)

            # Initialize the vulnerability count dictionary
            vulnerability_count = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}

            # Get the vulnerability counts grouped by severity
            machine_references = MachineReference.objects.filter(device__in=devices)
            severity_counts = machine_references.values('vulnerability__severity').annotate(count=Count('vulnerability__severity'))

            # Populate the vulnerability count dictionary
            for severity in severity_counts:
                severity_level = severity['vulnerability__severity']
                count = severity['count']
                if severity_level in vulnerability_count:
                    vulnerability_count[severity_level] = count

            # Update the resource group with the calculated vulnerability count
            resource_group.vulnerability_count = vulnerability_count
            resource_group.save()

            self.stdout.write(self.style.SUCCESS(f'Successfully updated {resource_group} with vulnerability counts'))
