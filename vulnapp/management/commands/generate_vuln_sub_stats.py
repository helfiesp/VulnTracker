import json
from django.core.management.base import BaseCommand
from django.utils.timezone import now
from django.db.models import Count
from vulnapp.models import Subscription, MachineReference, VulnerabilitySubStats

class Command(BaseCommand):
    help = 'Generate vulnerability statistics for all subscriptions and store in VulnerabilitySubStats.'

    def handle(self, *args, **kwargs):
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

            # Fetch vulnerability data related to the subscription by joining through Device
            vuln_data = MachineReference.objects.filter(
                device__subscription=subscription
            )

            # Get the count of vulnerabilities by severity for this subscription
            severity_statistics = vuln_data.values('vulnerability__severity').annotate(total_count=Count('vulnerability__severity'))

            # Populate the dictionary with counts of each severity
            for entry in severity_statistics:
                severity = entry['vulnerability__severity']
                total_count = entry['total_count']
                if severity in severity_stats_dict:
                    severity_stats_dict[severity] = total_count

            # Store the results in the VulnerabilitySubStats model
            # We no longer need to use json.dumps here as Django's JSONField handles serialization.
            VulnerabilitySubStats.objects.create(
                subscription_id=subscription.subscription_id,
                date_added=today,
                stats_vulnerabilities=severity_stats_dict  # Directly storing the dictionary
            )

            self.stdout.write(self.style.SUCCESS(f"Successfully generated vulnerability statistics for subscription {subscription.subscription_id}."))

        self.stdout.write(self.style.SUCCESS("Completed generating vulnerability statistics for all subscriptions."))