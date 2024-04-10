from django.core.management.base import BaseCommand, CommandError
import csv
from vulnapp.models import HostToBSS 

# This code is not used today
# The code was used to insert BSS data from a csv file from Kartoteket to match against hostnames.

class Command(BaseCommand):
    help = 'Import host and BSS data from a CSV file into the database'

    def add_arguments(self, parser):
        # Optional: Add arguments to command to customize functionality
        parser.add_argument('csv_file_path', type=str, help='Path to the CSV file containing the data.')

    def handle(self, *args, **options):
        csv_file_path = options['csv_file_path']
        try:
            # Attempt to open with a different encoding
            with open(csv_file_path, newline='', encoding='ISO-8859-1') as csvfile:
                csvreader = csv.reader(csvfile)
                
                # Skip the header row
                next(csvreader, None)
                
                for row in csvreader:
                    if len(row) < 2:
                        self.stdout.write(self.style.WARNING(f'Skipping row {row} due to insufficient data'))
                        continue
                    
                    host, bss = row[0], row[1]
                    HostToBSS.objects.create(host=host, bss=bss)
                    self.stdout.write(self.style.SUCCESS(f'Successfully inserted host "{host}" with BSS "{bss}"'))

        except FileNotFoundError:
            raise CommandError(f'File "{csv_file_path}" does not exist')
        except Exception as e:
            raise CommandError(f'An error occurred: {str(e)}')

