from django.core.management.base import BaseCommand, CommandError
from vulnapp.models import ShodanScanResult
import os
import shodan
from vulnapp import secrets

class Command(BaseCommand):
    help = 'Scans IP addresses in the 171.23.0.0/16 range and stores the results in the database'

    def handle(self, *args, **options):
        api_key = os.environ.get('SHODAN_API_SECRET')
        if not api_key:
            raise CommandError('SHODAN_API_SECRET environment variable not set')

        api = shodan.Shodan(api_key)
        ip_range = '171.23.0.0/16'

        try:
            page = 1
            while True:
                # Search Shodan with pagination
                results = api.search(f'net:{ip_range}', page=page)
                if not results['matches']:
                    break  # Exit loop if no more results
                
                for result in results['matches']:
                    ip_address = result['ip_str']
                    ShodanScanResult.objects.update_or_create(
                        ip_address=ip_address,
                        defaults={'data': result},
                    )
                    self.stdout.write(self.style.SUCCESS(f'Successfully added/updated {ip_address}'))
                
                page += 1

        except Exception as e:
            raise CommandError(f'Error fetching data from Shodan: {e}')
