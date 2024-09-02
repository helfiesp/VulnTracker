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
                machine_references = MachineReference.objects.filter(computer_dns_name__icontains=device.display_name.lower())
                print(machine_references)

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

