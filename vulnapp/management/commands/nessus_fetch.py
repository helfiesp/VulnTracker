import requests
from datetime import datetime
import time
import json
import csv
import subprocess
from django.core.management.base import BaseCommand
from vulnapp.models import NessusData
from django.conf import settings
import os
from pathlib import Path
from vulnapp import secrets

class Command(BaseCommand):
    help = 'Download Nessus scan data, perform NMAP scans, and save the results in the database.'

    def convert_csv_to_json(self, csv_data):
        json_data = []
        csv_reader = csv.DictReader(csv_data.splitlines())
        for row in csv_reader:
            json_data.append(row)
        return json_data

    def handle(self, *args, **options):
        scan_status = ScanStatus.objects.create(scan_type='Nessus_NMAP_Scan', status='in_progress', details='{}')
        scan_ids = [20]
        nmap_scans = {}
        nmap_scanned_hosts = []
        try:
            for scan_id in scan_ids:
                url = "https://nessus.okcsirt.no"
                access_key = os.environ["NESSUS_API_ACCESS_KEY"]
                secret_key = os.environ["NESSUS_API_SECRET_KEY"]
                headers = {"X-ApiKeys": f"accessKey={access_key};secretKey={secret_key}", "Content-Type": "application/x-www-form-urlencoded"}
                export_format_value = "csv"
                export_url = f"{url}/scans/{scan_id}/export"
                payload = {"format": export_format_value}
                response = requests.post(export_url, headers=headers, data=payload, verify=False)
                response.raise_for_status()
                response_data = response.json()
                download_export_id = response_data["file"]
                time.sleep(30)  # Consider making this wait time more dynamic or based on a response from the server.
                download_url = f"{url}/scans/{scan_id}/export/{download_export_id}/download"
                download_response = requests.get(download_url, headers=headers, verify=False)
                download_response.raise_for_status()
                exported_scan_data = download_response.content.decode("utf-8")
                json_data = self.convert_csv_to_json(exported_scan_data)
                NessusData.objects.create(data=json.dumps(json_data), scan_id=scan_id)
                scan_status.details = json.dumps({"last_processed_scan_id": scan_id})
                scan_status.save()

            scan_status.status = 'success'
            scan_status.save()
            self.stdout.write(self.style.SUCCESS('Successfully completed all Nessus and NMAP scanning processes.'))

        except requests.RequestException as e:
            self.stderr.write(f"Error: {e}")
            scan_status.status = 'error'
            scan_status.error_message = str(e)
            scan_status.save()