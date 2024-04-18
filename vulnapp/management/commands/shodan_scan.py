from django.core.management.base import BaseCommand, CommandError
from vulnapp.models import ShodanScanResult, ScanStatus
import os
import shodan
from vulnapp import secrets
import json

class Command(BaseCommand):
    help = 'Scans IP addresses in the 171.23.0.0/16 range and stores the results in the database'

    def handle(self, *args, **options):
        api_key = os.environ.get('SHODAN_API_SECRET')
        if not api_key:
            raise CommandError('SHODAN_API_SECRET environment variable not set')

        api = shodan.Shodan(api_key)
        ip_range = '171.23.0.0/16'
        scan_status = ScanStatus.objects.create(scan_type='Shodan_IP_Range_Scan', status='in_progress', details='{}')

        try:
            page = 1
            processed_ips = 0
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
                    processed_ips += 1
                    self.stdout.write(self.style.SUCCESS(f'Successfully added/updated {ip_address}'))
                
                page += 1

            scan_status.status = 'success'
            scan_status.details = json.dumps({"processed_ips": processed_ips})
            scan_status.save()
            self.stdout.write(self.style.SUCCESS('Successfully completed the Shodan IP range scan.'))

        except Exception as e:
            self.stderr.write(f'Error: {e}')
            scan_status.status = 'error'
            scan_status.error_message = str(e)
            scan_status.save()
            raise CommandError(f'Error fetching data from Shodan: {e}')