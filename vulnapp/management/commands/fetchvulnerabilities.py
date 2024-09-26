from django.core.management.base import BaseCommand, CommandError
from dateutil.parser import parse
import requests
from vulnapp.models import Vulnerability, ScanStatus, VulnerabilityStats
from vulnapp import secrets
import os
import json
from django.db.models import Count, Sum
from django.utils.timezone import now

class Command(BaseCommand):
    help = 'Imports vulnerability data from Microsoft Security Center API and updates vulnerability statistics.'

    def parse_datetime(self, date_string):
        if date_string:
            return parse(date_string).date()
        return None

    def fetch_auth_token(self):
        url = "https://login.microsoftonline.com/{}/oauth2/v2.0/token".format(os.environ["MICROSOFT_TENANT_ID"])
        payload = {
            "client_id": os.environ["MICROSOFT_CLIENT_ID"],
            "scope": "https://api.securitycenter.microsoft.com/.default",
            "client_secret": os.environ["MICROSOFT_CLIENT_SECRET"],
            "grant_type": "client_credentials"
        }
        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }
        response = requests.post(url, data=payload, headers=headers)

        if response.status_code == 200:
            print("Fetched auth token.")
            data = response.json()
            return data["access_token"]
        else:
            raise CommandError('Failed to fetch authentication token.')

    def handle(self, *args, **options):
        scan_status = ScanStatus.objects.create(scan_type='Microsoft_Vulnerability_Import', status='in_progress', details='{}')
        try:
            BEARER_TOKEN = self.fetch_auth_token()
            headers = {
                'Authorization': f'Bearer {BEARER_TOKEN}',
                'Content-Type': 'application/json'
            }
            base_url = "https://api.securitycenter.microsoft.com/api/Vulnerabilities"
            page_size = 8000
            skip = 0
            processed_count = 0

            while True:
                url = f"{base_url}?$top={page_size}&$skip={skip}"
                response = requests.get(url, headers=headers)

                if response.status_code == 200:
                    vulnerabilities = response.json()["value"]
                    for vuln_data in vulnerabilities:
                        processed_count += 1

                        published_on = self.parse_datetime(vuln_data['publishedOn'])
                        updated_on = self.parse_datetime(vuln_data['updatedOn'])
                        first_detected = self.parse_datetime(vuln_data.get('firstDetected'))
                        if vuln_data.get('exposedMachines', 0) > 0:
                            print("Processed vulnerability: {} with {} exposed machines".format(vuln_data['name'], vuln_data.get('exposedMachines', 0)))
                            Vulnerability.objects.update_or_create(
                                id=vuln_data['id'],
                                defaults={
                                    'name': vuln_data['name'],
                                    'description': vuln_data['description'],
                                    'severity': vuln_data['severity'],
                                    'cvssV3': vuln_data.get('cvssV3'),
                                    'cvssVector': vuln_data.get('cvssVector', ''),
                                    'exposedMachines': vuln_data.get('exposedMachines', 0),
                                    'publishedOn': published_on,
                                    'updatedOn': updated_on,
                                    'firstDetected': first_detected,
                                    'publicExploit': vuln_data.get('publicExploit', False),
                                    'exploitVerified': vuln_data.get('exploitVerified', False),
                                    'exploitInKit': vuln_data.get('exploitInKit', False),
                                    'exploitTypes': vuln_data.get('exploitTypes', []),
                                    'exploitUris': vuln_data.get('exploitUris', []),
                                    'cveSupportability': vuln_data.get('cveSupportability', ''),
                                }
                            )

                    if len(vulnerabilities) < page_size:
                        break  # Exit the loop if we fetched fewer items than requested

                    skip += page_size  # Prepare for the next page of vulnerabilities
                else:
                    raise CommandError(f"Failed to fetch data: {response.status_code}")

            # After successfully processing, update the ScanStatus
            scan_status.status = 'success'
            scan_status.details = json.dumps({"processed_vulnerabilities": processed_count})
            scan_status.save()

            # Generate and save vulnerability statistics
            self.generate_and_save_vuln_stats()

            self.stdout.write(self.style.SUCCESS(f"Successfully processed {processed_count} vulnerabilities and updated statistics."))

        except Exception as e:
            self.stdout.write(self.style.ERROR(f'An error occurred: {str(e)}'))
            scan_status.status = 'error'
            scan_status.error_message = str(e)
            scan_status.save()

    def generate_and_save_vuln_stats(self):
        vulnerabilities = Vulnerability.objects.filter(exposedMachines__gt=0)

        # Calculate statistics
        vulnerabilities_stats = vulnerabilities.values('severity').annotate(total=Count('id')).order_by('severity')
        exposed_machines_stats = vulnerabilities.values('severity').annotate(exposed_total=Sum('exposedMachines')).order_by('severity')
        known_exploited_stats = vulnerabilities.filter(publicExploit=True).aggregate(
            known_exploited_count=Count('id'), 
            known_exploited_exposed_machines=Sum('exposedMachines')
        )

        # Initialize stats dictionaries
        stats_vulnerabilities = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Known_Exploited': known_exploited_stats['known_exploited_count']}
        stats_exposed_machines = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Known_Exploited': known_exploited_stats['known_exploited_exposed_machines']}

        # Fill stats for vulnerabilities
        for stat in vulnerabilities_stats:
            if stat['severity'] in stats_vulnerabilities:
                stats_vulnerabilities[stat['severity']] = stat['total']

        # Fill stats for exposed machines
        for stat in exposed_machines_stats:
            if stat['severity'] in stats_exposed_machines:
                stats_exposed_machines[stat['severity']] = stat['exposed_total']

        # Create a new entry in the VulnerabilityStats model
        VulnerabilityStats.objects.create(
            date_added=now(),
            stats_vulnerabilities=json.dumps(stats_vulnerabilities),
            stats_exposed_machines=json.dumps(stats_exposed_machines)
        )
