import json
from django.core.management.base import BaseCommand
from django.utils.timezone import now
from django.db.models import Count
from vulnapp.models import Subscription, Device, MachineReference, VulnerabilitySubStats

class Command(BaseCommand):
    help = 'Generate vulnerability statistics for all subscriptions and store in VulnerabilitySubStats.'

    def generate_and_save_vuln_stats()
        # Get today's date
        today = now().date()

        # **Delete all existing data in VulnerabilitySubStats**
        VulnerabilitySubStats.objects.all().delete()
        self.stdout.write(self.style.WARNING(f"Deleted all existing VulnerabilitySubStats records."))

        # Fetch all subscriptions
        subscriptions = Subscription.objects.all()

        for subscription in subscriptions:
            # Initialize a dictionary to hold severity-level vulnerability stats
            severity_stats_dict = {
                'Critical': 0,
                'High': 0,
                'Medium': 0,
                'Low': 0,
            }

            # Fetch all devices related to the subscription
            devices = Device.objects.filter(subscription=subscription)

            total_vulnerabilities = 0  # Initialize total vulnerabilities count for the subscription

            for device in devices:
                # Fetch MachineReference objects for the current device (based on the device's display name)
                vuln_data = MachineReference.objects.filter(computer_dns_name__icontains=device.display_name)

                if vuln_data.filter(last_updated__date=today).exists():
                    # Count vulnerabilities for today
                    vuln_count = vuln_data.count()
                    total_vulnerabilities += vuln_count
                else:
                    # If no data is available for today
                    vuln_count = 0  # Set to 0 if no vulnerabilities are found today

                # Fetch severity statistics for the vulnerabilities associated with this device
                severity_statistics = vuln_data.values('vulnerability__severity').annotate(total_count=Count('vulnerability__severity'))

                # Combine all entries of each severity level into the subscription-level dictionary
                for entry in severity_statistics:
                    severity = entry['vulnerability__severity']
                    total_count = entry['total_count']
                    if severity in severity_stats_dict:
                        severity_stats_dict[severity] += total_count
                    else:
                        severity_stats_dict[severity] = total_count

            # Store the results in the VulnerabilitySubStats model
            VulnerabilitySubStats.objects.create(
                subscription_id=subscription.subscription_id,
                date_added=today,
                stats_vulnerabilities=severity_stats_dict  # Directly storing the dictionary
            )

            self.stdout.write(self.style.SUCCESS(f"Successfully generated vulnerability statistics for subscription {subscription.subscription_id} with {total_vulnerabilities} total vulnerabilities."))

        self.stdout.write(self.style.SUCCESS("Completed generating vulnerability statistics for all subscriptions."))
