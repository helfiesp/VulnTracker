# your_app/management/commands/authenticate_mend.py

from django.core.management.base import BaseCommand
import requests
import os
from vulnapp import secrets

class Command(BaseCommand):
    help = 'Authenticate to Mend Whitesource API 2.0 and retrieve an access token.'

    def handle(self, *args, **options):
        # Retrieve the user key from an environment variable
        user_key = os.environ["WHITESOURCE_API_KEY"]

        if not user_key:
            self.stderr.write(self.style.ERROR('User key not found. Please set the MEND_USER_KEY environment variable.'))
            return

        url = 'https://api-app-eu.whitesourcesoftware.com'

        payload = {
            "userKey": user_key
        }

        headers = {
            'Content-Type': 'application/json'
        }

        try:
            response = requests.post(url, json=payload, headers=headers)
            response.raise_for_status()  # Check for HTTP errors
            data = response.json()
            access_token = data.get('access_token')
            expires_in = data.get('expires_in')

            if access_token:
                self.stdout.write(self.style.SUCCESS(f'Access token: {access_token}'))
                self.stdout.write(f'Expires in: {expires_in} seconds')
            else:
                self.stderr.write(self.style.ERROR('Authentication failed. No access token returned.'))

        except requests.exceptions.HTTPError as errh:
            self.stderr.write(self.style.ERROR(f'HTTP Error: {errh}'))
        except requests.exceptions.ConnectionError as errc:
            self.stderr.write(self.style.ERROR(f'Error Connecting: {errc}'))
        except requests.exceptions.Timeout as errt:
            self.stderr.write(self.style.ERROR(f'Timeout Error: {errt}'))
        except requests.exceptions.RequestException as err:
            self.stderr.write(self.style.ERROR(f'An error occurred: {err}'))
