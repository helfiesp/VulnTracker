from django.core.management.base import BaseCommand, CommandError
from vulnapp.models import HaveIBeenPwnedBreaches, HaveIBeenPwnedBreachedAccounts
import requests
from django.conf import settings
import os
import json

api_key = os.environ["HAVEIBEENPWNED_API_KEY"]

class Command(BaseCommand):
    help = 'Fetches data from HaveIBeenPwned API and updates the database'

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS('Starting the breach data update process...'))
        self.fetch_and_update_breaches()
        self.fetch_breached_domains()

    def fetch_and_update_breaches(self):
        headers = {
            "hibp-api-key": api_key,
            "Content-Type": "application/json"
        }
        api_endpoint = "https://haveibeenpwned.com/api/v3/breaches"

        response = requests.get(api_endpoint, headers=headers, verify=False)
        if response.status_code == 200:
            breaches_data = response.json()
            for item in breaches_data:
                breach, created = HaveIBeenPwnedBreaches.objects.update_or_create(
                    name=item.get('Name', ''),
                    defaults={
                        'title': item.get('Title', ''),
                        'domain': item.get('Domain', ''),
                        'breach_date': item.get('BreachDate', ''),
                        'added_date': item['AddedDate'],
                        'modified_date': item['ModifiedDate'],
                        'pwn_count': item.get('PwnCount', 0),
                        'description': item.get('Description', ''),
                        'logo_path': item.get('LogoPath', ''),
                        'data_classes': json.dumps(item.get('DataClasses', [])),
                        'is_verified': item.get('IsVerified', False),
                        'is_fabricated': item.get('IsFabricated', False),
                        'is_sensitive': item.get('IsSensitive', False),
                        'is_retired': item.get('IsRetired', False),
                        'is_spam_list': item.get('IsSpamList', False),
                        'is_malware': item.get('IsMalware', False),
                        'is_subscription_free': item.get('IsSubscriptionFree', False),
                    }
                )
                if created:
                    self.stdout.write(self.style.SUCCESS(f"Added new breach: {breach.name}"))
                else:
                    self.stdout.write(self.style.SUCCESS(f"Updated breach: {breach.name}"))
        else:
            self.stdout.write(self.style.ERROR('Failed to fetch data'))

    def fetch_breached_domains(self):
        # Load domains from a file
        domains_list_path = os.path.join(settings.BASE_DIR, 'static', 'files', 'hibp_domains.txt')
        with open(domains_list_path, 'r') as file:
            domains = [line.strip() for line in file]

        headers = {
            'hibp-api-key': api_key,
            'Accept': 'application/json'
        }

        for domain in domains:
            self.check_breached_accounts_for_domain(domain, headers)

    def check_breached_accounts_for_domain(self, domain, headers):
        api_endpoint = f"https://haveibeenpwned.com/api/v3/breacheddomain/{domain}"
        response = requests.get(api_endpoint, headers=headers, verify=False)

        if response.status_code == 200:
            breaches_data = response.json()
            for user, breached_sites in breaches_data.items():
                # Construct the email address using the provided user and domain
                email_address = f"{user}@{domain}"
                
                # Directly use the list of breached sites without additional detail fetching
                obj, created = HaveIBeenPwnedBreachedAccounts.objects.update_or_create(
                    email_address=email_address,
                    defaults={
                        'breached_sites': json.dumps(breached_sites),  # Store the list of breached sites as a JSON string
                    }
                )
                action = "Added" if created else "Updated"
                self.stdout.write(self.style.SUCCESS(f"{action} breached account for: {email_address}"))
        elif response.status_code == 404:
            self.stdout.write(self.style.NOTICE(f"No breach data found for domain: {domain}"))
        else:
            self.stdout.write(self.style.ERROR(f"Failed to fetch breach data for domain: {domain}, Status Code: {response.status_code}"))

