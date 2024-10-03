import os
import requests
from django.core.management.base import BaseCommand
from requests.exceptions import RequestException
from vulnapp import secrets

class Command(BaseCommand):
    help = 'Fetch all data from Whitesource Mend API and print to console'

    def handle(self, *args, **options):
        # API key and endpoint configuration
        api_key = os.environ['WHITESOURCE_API_KEY']  # Set this environment variable
        base_url = 'https://api-app-eu.whitesourcesoftware.com'  # API base URL according to the documentation

        if not api_key:
            self.stderr.write(self.style.ERROR('API key is not set. Set the WHITESOURCE_API_KEY environment variable.'))
            return

        # Headers and parameters
        headers = {
            'Authorization': f'Bearer {api_key}',
            'Accept': 'application/json'
        }

        # Define the initial endpoint to start fetching data
        endpoint = f'{base_url}projects'

        try:
            response = requests.get(endpoint, headers=headers)
            response.raise_for_status()

            # Print out the retrieved data for now (later, we will save this into models)
            data = response.json()
            self.stdout.write(self.style.SUCCESS(f'Successfully fetched data: {data}'))

        except RequestException as e:
            self.stderr.write(self.style.ERROR(f'Failed to fetch data: {e}'))

# Notes:
# - You will need to add your API key in the environment as 'WHITESOURCE_API_KEY'.
# - This command fetches data from the `/projects` endpoint as a starting point.
# - We will iterate on this once we know more details about the data structure.