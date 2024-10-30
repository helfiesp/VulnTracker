from django.shortcuts import render, redirect
from django.http import HttpResponse
from .models import CVE, Keyword, Blacklist
from .forms import KeywordForm, UploadIPCSVForm, KeywordUploadForm, BlacklistForm, CMDBForm, TicketForm
import csv
from django.utils import timezone
from datetime import timedelta
from django.shortcuts import render, get_object_or_404
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from django.views.decorators.http import require_POST
from django.contrib.contenttypes.models import ContentType
import json
from django.shortcuts import render
from django.utils import timezone
from datetime import timedelta
import os
from collections import defaultdict
from datetime import datetime
from django.db.models.functions import Lower
import requests
from django.db import transaction
import re
from django.db.models import Prefetch
from django.db.models import Sum
from django.http import HttpResponseRedirect
from django.db.models.functions import ExtractYear
from django.db.models import Count, Q, Sum
from django.urls import reverse, NoReverseMatch
from .models import VulnerabilityStats, VulnerabilitySubStats, Subscription, ResourceGroup, Device, CVE, Comment, PublicIP, CMDB, Ticket, NessusData, Vulnerability, MachineReference, HaveIBeenPwnedBreaches, HaveIBeenPwnedBreachedAccounts, Software, SoftwareHosts, ScanStatus, ShodanScanResult
from vulnapp import secrets

def index(request):
    """
    Index function to display the main page.
    This page displays the CVE information from NVD as well as scan status.
    """

    # Get current time
    now = timezone.now()
    # Retrieve sorting parameters from the GET request
    sort_by = request.GET.get('sort_by', 'cvss_score_desc')  # Default to 'cvss_score_desc'
    order = request.GET.get('order', 'desc')
    
    # Retrieve date filter parameter from the GET request
    date_filter = request.GET.get('date_filter', 'past_day')
    keywords_only = request.GET.get('keywords', 'false') == 'true'


    # Start with all CVEs
    cves = CVE.objects.all()

    # Apply date filter
    if date_filter == 'past_day':
        start_date = now - timedelta(days=1)
        cves = cves.filter(published_date__gte=start_date)
    elif date_filter == 'past_week':
        start_date = now - timedelta(days=7)
        cves = cves.filter(published_date__gte=start_date)
    elif date_filter == 'past_weekend':
        weekend_start = now - timedelta(days=now.weekday() + 2)  # Get the last Friday
        weekend_end = weekend_start + timedelta(days=2)  # Weekend is Friday to Sunday
        cves = cves.filter(published_date__range=(weekend_start, weekend_end))
    elif date_filter == 'this_month':
        start_date = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        cves = cves.filter(published_date__gte=start_date)

    # Apply keyword filter if exists
    keyword_filter = request.GET.get('keyword', '')
    if keyword_filter:
        cves = cves.filter(keywords__icontains=keyword_filter)

    # Filter to show only CVEs with keywords
    if keywords_only:
        cves = cves.exclude(keywords='')

    # Apply sorting
    if sort_by == 'cvss_score_desc':
        cves = cves.order_by('-cvss_score')
    elif sort_by == 'cvss_score_asc':
        cves = cves.order_by('cvss_score')
    elif sort_by == 'date_desc':
        cves = cves.order_by('-published_date')
    elif sort_by == 'date_asc':
        cves = cves.order_by('published_date')

    return render(request, 'index.html', {
        'cves': cves,
        'current_sort': sort_by,
        'current_order': order,
        'current_date_filter': date_filter,
        'scan_status': fetch_scan_info()
    })

def fetch_scan_info():
    """
    Function to fetch scan status.
    The scan status is recorded whenever a scanning script is executed, to track the status of the scan.
    """

    unique_scan_types = ScanStatus.objects.values_list('scan_type', flat=True).distinct()

    # Then, for each type, get the most recent scan
    recent_scans = []
    for scan_type in unique_scan_types:
        recent_scan_for_type = ScanStatus.objects.filter(scan_type=scan_type).latest('completed_at')
        recent_scans.append(recent_scan_for_type)
    return recent_scans

def keyword_view(request):
    """
    Functon to show existing keywords and add new keywords to the CVE filter.
    The user can input a single keyword or upload a CSV format.
    """
    if request.method == 'POST':
        # Check which form is being submitted
        if 'submit_keyword' in request.POST:
            keyword_form = KeywordForm(request.POST)
            upload_form = KeywordUploadForm()  # Initialize an empty form for rendering
            if keyword_form.is_valid():
                keyword_form.save()
                return redirect('keywords')
        elif 'upload_csv' in request.POST:
            keyword_form = KeywordForm()  # Initialize an empty form for rendering
            upload_form = KeywordUploadForm(request.POST, request.FILES)
            if upload_form.is_valid():
                file = request.FILES['file']
                reader = csv.reader(file.read().decode('utf-8').splitlines())
                for row in reader:
                    keyword, created = Keyword.objects.get_or_create(word=row[0].strip())  # Assuming one keyword per row
                return redirect('keywords')
    else:
        keyword_form = KeywordForm()
        upload_form = KeywordUploadForm()

    keywords = Keyword.objects.all()
    return render(request, 'keywords.html', {'keyword_form': keyword_form, 'upload_form': upload_form, 'keywords': keywords})

def blacklist_view(request):
    """
    Function to add keywords to blacklist.
    Some keywords are automatically generated by the software inventory, and this might not always provide correct results, or produce false positives.
    Therefore this function is used to remove these words.
    """

    if request.method == 'POST':
        # Check which form is being submitted
        if 'submit_blacklist' in request.POST:
            blacklist_form = BlacklistForm(request.POST)  # Re-assign with POST data if needed
            if blacklist_form.is_valid():
                blacklist_form.save()
                return redirect('blacklist')
    else:
        blacklist_form = BlacklistForm()

    blacklist_entries = Blacklist.objects.all()
    for x in blacklist_entries:
        print("X: {}".format(x))
    return render(request, 'blacklist.html', {'blacklist_form': blacklist_form, 'blacklist': blacklist_entries})

@csrf_exempt
def delete_word(request, model_name, word_id):
    """
    The function is called whenever the user decides to delete word in the keywords or blacklist model.
    """
    
    if request.method == 'DELETE':
        model = Blacklist if model_name == 'blacklist' else Keyword if model_name == 'keyword' else None
        if not model:
            return JsonResponse({'status': 'error', 'message': 'Invalid model'}, status=400)
        try:
            word = model.objects.get(pk=word_id)
            word.delete()
            return JsonResponse({'status': 'success'}, status=200)
        except model.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'Word not found'}, status=404)
    else:
        return JsonResponse({'status': 'error', 'message': 'Invalid request'}, status=400)

def defender_vulnerabilities(request):
    public_exploit_filter = request.GET.get('publicExploit', 'false') == 'true'
    vulnerabilities = Vulnerability.objects.filter(exposedMachines__gt=0)
    
    if public_exploit_filter:
        vulnerabilities = vulnerabilities.filter(publicExploit=True)

    # Sort by cvssV3 (descending) first, then by exposedMachines (descending)
    vulnerabilities = vulnerabilities.order_by('-cvssV3', '-exposedMachines')

    vuln_stats = generate_vuln_stats(vulnerabilities)
    stats = {
        'vulnerabilities': vuln_stats[0],
        'exposed_machines': vuln_stats[1],
        'Total_Vulnerabilities': vuln_stats[2],
        'Total_Exposed_Machines': vuln_stats[3]
    }

    return render(request, 'defender_vulnerabilities.html', {'vulnerabilities': vulnerabilities, 'stats': stats})

def generate_vuln_stats(vulnerabilities):
    # Calculate statistics
    vulnerabilities_stats = vulnerabilities.values('severity').annotate(total=Count('id')).order_by('severity')
    exposed_machines_stats = vulnerabilities.values('severity').annotate(exposed_total=Sum('exposedMachines')).order_by('severity')
    known_exploited_stats = vulnerabilities.filter(publicExploit=True).aggregate(
        known_exploited_count=Count('id'), 
        known_exploited_exposed_machines=Sum('exposedMachines')
    )
    
    total_vulnerabilities = vulnerabilities.count()
    total_exposed_machines = vulnerabilities.aggregate(Sum('exposedMachines'))['exposedMachines__sum'] or 0

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

    return stats_vulnerabilities, stats_exposed_machines, total_vulnerabilities, total_exposed_machines


def defender_vulnerabilities_stats(request):
    # Fetch all stats ordered by date
    all_stats = VulnerabilityStats.objects.order_by('-date_added')
    
    # Optionally filter by date if provided in request
    selected_date_str = request.GET.get('date', None)
    print("Selected Date (Raw):", selected_date_str)  # Debug statement
    selected_date = None

    if selected_date_str:
        try:
            # Parse the date from the string in the expected format (YYYY-MM-DD)
            selected_date = datetime.strptime(selected_date_str, "%Y-%m-%d").date()
        except ValueError:
            # Handle invalid date format
            selected_date = None

    if selected_date:
        print("SELECTED: {}".format(selected_date))
        # Use exact match for the date_added field to ensure proper comparison
        stats = all_stats.filter(date_added__exact=selected_date).first()
        sub_stats = VulnerabilitySubStats.objects.filter(date_added__exact=selected_date)
    else:
        print("DEFAULT")
        # Default to the latest stats if no date is selected or parsing fails
        stats = all_stats.first()
        sub_stats = VulnerabilitySubStats.objects.filter(date_added=stats.date_added) if stats else []

    if stats:
        # Prepare subscription stats data, but only include subscriptions with non-zero values
        subscription_stats_list = []
        for sub_stat in sub_stats:
            severity_stats = sub_stat.stats_vulnerabilities

            # Fetch the subscription object based on subscription_id
            subscription = Subscription.objects.filter(subscription_id=sub_stat.subscription_id).first()

            # Check if all values are 0, if so, skip this subscription
            if any(severity_stats.get(key, 0) > 0 for key in ['Critical', 'High', 'Medium', 'Low']):
                subscription_stats_list.append({
                    'subscription_id': sub_stat.subscription_id,
                    'subscription_name': subscription.display_name, 
                    'severity_stats': severity_stats  # No need for json.loads here
                })
        
        context = {
            'stats': {
                'vulnerabilities': stats.stats_vulnerabilities,
                'exposed_machines': stats.stats_exposed_machines,
            },
            'available_dates': all_stats.values_list('date_added', flat=True),
            'selected_date': stats.date_added.strftime("%Y-%m-%d"),  # Send the formatted date to match the template dropdown value
            'subscription_stats': json.dumps(subscription_stats_list)  # Pass as JSON to frontend
        }
    else:
        # Handle the case where no stats are available
        context = {
            'stats': {
                'vulnerabilities': {},
                'exposed_machines': {},
            },
            'available_dates': all_stats.values_list('date_added', flat=True),
            'selected_date': None,
            'subscription_stats': json.dumps([])  # No subscription stats available
        }

    return render(request, 'defender_vulnerabilities_stats.html', context)

def generate_unique_comment_id(cve_id, machine_id):
    """
    Simply generates a custom id to identify a coment
    """
    return f"{cve_id}__{machine_id}"


def fetch_auth_token():
    """
    Fetches the auth token in order to be able to access the Microsoft API.
    This auth token is only available for a short period of time, so this has to be called upon each request.
    """

    url = "https://login.microsoftonline.com/{}/oauth2/v2.0/token".format(os.environ["MICROSOFT_TENANT_ID"])
    payload = {
        "client_id": os.environ["MICROSOFT_CLIENT_ID"],
        "scope": "https://api.securitycenter.microsoft.com/.default",
        "client_secret": os.environ["MICROSOFT_CLIENT_SECRET"],
        "grant_type": "client_credentials"
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    response = requests.post(url, data=payload, headers=headers)
    if response.status_code == 200:
        data = response.json()
        return data["access_token"]
    else:
        raise CommandError('Failed to fetch authentication token.')

def fetch_machine_references_for_cve_from_api(cve_id, token):
    """Fetch machine references for a specific CVE ID from the API."""
    headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}
    url = f"https://api.securitycenter.microsoft.com/api/vulnerabilities/{cve_id}/machineReferences"
    
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()["value"]
    return None

def save_machine_references_from_api(cve, machine_data_list):
    """Process and save machine data fetched from the API."""
    with transaction.atomic():
        for machine_data in machine_data_list:
            MachineReference.objects.create(
                vulnerability=cve,
                machine_id=machine_data['id'],
                computer_dns_name=machine_data.get('computerDnsName'),
                os_platform=machine_data.get('osPlatform'),
                rbac_group_name=machine_data.get('rbacGroupName', ''),
                rbac_group_id=machine_data.get('rbacGroupId', None),
                detection_time=parse(machine_data.get('detectionTime')) if machine_data.get('detectionTime') else None,
            )

def machine_list(request, cve_id):

    """
    View function to show all affected hosts for a specified CVE.

    """
    cve = get_object_or_404(Vulnerability, id=cve_id)
    machines = cve.machine_references.all()
    is_fetching_from_api = False  # Default to False

    if not machines.exists():
        token = fetch_auth_token()
        if token:
            is_fetching_from_api = True
            api_machines = fetch_machine_references_for_cve_from_api(cve_id, token)
            if api_machines:
                save_machine_references_from_api(cve, api_machines)
                machines = cve.machine_references.all() 
                is_fetching_from_api = False 

    machine_content_type = ContentType.objects.get_for_model(MachineReference)

    # Counting machines by RBAC Group Name
    rbac_group_name_counts = machines.values('rbac_group_name').annotate(count=Count('rbac_group_name'))

    # Counting servers and clients separately
    server_count = machines.filter(Q(os_platform__icontains='server') | Q(rbac_group_name__icontains='server')).count()
    client_count = machines.filter(~Q(os_platform__icontains='server') & ~Q(rbac_group_name__icontains='server')).count()


    for machine in machines:
        unique_id = generate_unique_comment_id(cve_id, machine.machine_id)
        comments = Comment.objects.filter(
            content_type=machine_content_type,
            object_id=unique_id
        ).order_by('-created_at')
        machine.comment_content = comments[0].content if comments.exists() else ""
        # Fetch the corresponding device information
        # Fetch all devices matching the display name, case-insensitively
        try:
            machine.device_info = Device.objects.filter(display_name=str(machine.computer_dns_name)).get()
        except:
            machine.device_info = None


    # Existing filter logic for OS Platforms and RBAC Group Names
    os_platforms = machines.order_by('os_platform').values_list('os_platform', flat=True).distinct()
    rbac_group_names = machines.order_by('rbac_group_name').values_list('rbac_group_name', flat=True).distinct()
    selected_os_platform = request.GET.get('os_platform')
    if selected_os_platform:
        machines = machines.filter(os_platform=selected_os_platform)
    selected_rbac_group_name = request.GET.get('rbac_group_name')
    if selected_rbac_group_name:
        machines = machines.filter(rbac_group_name=selected_rbac_group_name)

    # New filter logic for Server/Client
    selected_machine_type = request.GET.get('machine_type')
    if selected_machine_type == 'server':
        machines = machines.filter(Q(os_platform__icontains='server') | Q(rbac_group_name__icontains='server'))
    elif selected_machine_type == 'client':
        machines = machines.exclude(Q(os_platform__icontains='server') | Q(rbac_group_name__icontains='server'))

    context = {
        'cve': cve,
        'machines': machines,
        'os_platforms': os_platforms,
        'rbac_group_names': rbac_group_names,
        'selected_os_platform': selected_os_platform,
        'selected_rbac_group_name': selected_rbac_group_name,
        'rbac_group_name_counts': rbac_group_name_counts,
        'server_count': server_count,
        'client_count': client_count,
        'selected_machine_type': selected_machine_type,
        'is_fetching_from_api': is_fetching_from_api,
    }
    return render(request, 'machine_list.html', context)


def fetch_vulnerabilities_for_machine_from_api(computer_dns_name, token):
    """Fetch all CVEs associated with a specific machine from the API."""
    headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}
    # The API endpoint as per Microsoft's documentation, adjust if necessary
    url = f"https://api.securitycenter.microsoft.com/api/machines/{computer_dns_name}/vulnerabilities"
    
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()["value"]
    else:
        return None

def cve_list_for_machine(request, computer_dns_name):
    """
    View function to show all vulnerabilities for a specific host and provide statistics on CVE severity.
    """
    machine_references = MachineReference.objects.filter(computer_dns_name__icontains=computer_dns_name)
    software_list = Software.objects.filter(software_hosts__computer_dns_name__icontains=computer_dns_name).distinct()

    # Initial CVE queryset sorted by CVSS score in descending order
    cves = Vulnerability.objects.filter(machine_references__in=machine_references).distinct().order_by('-cvssV3')

    # Fetch associated comments for each CVE
    for cve in cves:
        # Fetch the latest comment for each CVE (adjust based on your actual model structure)
        latest_comment = Comment.objects.filter(
            content_type=ContentType.objects.get_for_model(Vulnerability),
            object_id=cve.id
        ).order_by('-created_at').first()

        # Attach the latest comment content to the CVE object (if it exists)
        cve.latest_comment = latest_comment.content if latest_comment else ''


    # Extract device info and machine-specific data from one entry in machine_references
    example_reference = None
    if machine_references.exists():
        example_reference = machine_references.first()

    # Modify the queryset to count the number of CVEs for each severity
    severity_statistics = cves.values('severity').annotate(total_count=Count('severity'))

    # Combine all entries of each severity level into a single dictionary element
    severity_stats_dict = {}
    for entry in severity_statistics:
        severity = entry['severity']
        total_count = entry['total_count']
        if severity in severity_stats_dict:
            severity_stats_dict[severity] += total_count
        else:
            severity_stats_dict[severity] = total_count

    # Device info
    try:
        try:
            device_info_queryset = Device.objects.filter(display_name=str(computer_dns_name)).get()
        except:
            device_info_queryset = Device.objects.filter(display_name=str(computer_dns_name).upper()).get()
    except:
        device_info_queryset = None

    context = {
        'cves': cves,
        'software_list': software_list,
        'machine_id': computer_dns_name,
        'severity_stats': json.dumps(severity_stats_dict),
        'machine_reference': example_reference,
        'device_info': device_info_queryset
    }
    return render(request, 'cve_list_for_machine.html', context)



# HAVEIBEENPWNED SECTION START
def haveibeenpwned_breaches(request):
    """
    Fetches all unique breaches and shows them in a view.
    """
    sort_by = request.GET.get('sort', 'pwn_count_desc')
    filter_year = request.GET.get('filter_year', None)

    # Get unique years from breach dates
    years = HaveIBeenPwnedBreaches.objects.annotate(year=ExtractYear('breach_date')).values_list('year', flat=True).distinct().order_by('-year')

    # Filter breaches based on the selected year
    breaches = HaveIBeenPwnedBreaches.objects.all()
    if filter_year:
        breaches = breaches.filter(breach_date__year=filter_year)

    # Adjust sorting here before adding dynamic attributes
    if sort_by in ['pwn_count_desc', 'pwn_count_asc']:
        if sort_by == 'pwn_count_desc':
            breaches = breaches.order_by('-pwn_count')
        elif sort_by == 'pwn_count_asc':
            breaches = breaches.order_by('pwn_count')
    
    # Convert QuerySet to list for dynamic sorting
    breaches_list = list(breaches)

    # Add breached_users to each breach object
    for breach in breaches_list:
        breached_users = get_users_for_breach(breach)
        breach.breached_users = breached_users
        breach.breached_users_count = len(breached_users)  # Store count for sorting

    # Sort by breached_users_count if required
    if sort_by in ['breached_users_desc', 'breached_users_asc']:
        breaches_list.sort(key=lambda x: x.breached_users_count, reverse=(sort_by == 'breached_users_desc'))

    context = {
        'breaches': breaches_list,  # Use the sorted list
        'current_sort': sort_by,
        'years': years,
        'current_filter_year': filter_year,
    }
    return render(request, 'haveibeenpwned.html', context)


def get_users_for_breach(breach):
    """
    Fetches all breached users for a haveibeenpwned breach.
    Helper function for haveibeenpwned_breaches
    """
    breached_accounts = HaveIBeenPwnedBreachedAccounts.objects.filter(breached_sites__contains=breach.name)
    users = []
    for account in breached_accounts:
        users.append(account.email_address)
    return users


def get_breaches_for_user(request, email):
    """
    Fetches all breaches that a specific user has been involved in.
    """
    breaches = []
    search_email = email
    # Assuming the breached_sites field is a JSON-encoded list of breach names
    breached_accounts = HaveIBeenPwnedBreachedAccounts.objects.filter(email_address=search_email)
    breached_sites_names = []
    for account in breached_accounts:
        breached_sites_names.extend(json.loads(account.breached_sites))

    breaches = HaveIBeenPwnedBreaches.objects.filter(name__in=breached_sites_names).distinct()
    for breach in breaches:
        breached_users = get_users_for_breach(breach)
        breach.breached_users = breached_users 

    context = {
        'breaches': breaches,
        'breached_user': search_email,
    }
    return render(request, 'haveibeenpwned.html', context)

def breached_users_list(request, breach_name):
    """
    Fetches all breached users for a specific breach and shows them to the user in the template.
    """
    breach = get_object_or_404(HaveIBeenPwnedBreaches, name=breach_name)
    breached_accounts = HaveIBeenPwnedBreachedAccounts.objects.filter(breached_sites__contains=breach.name)
    users = [account.email_address for account in breached_accounts]

    # Map visual names to full domains
    section_map = {}
    for user in users:
        full_domain = user.split('@')[1]
        visual_name = full_domain.replace(".no", "").replace(".oslo.kommune", "")
        if len(visual_name) == 3:
            visual_name = visual_name.upper()
        else:
            visual_name = visual_name.capitalize()
        section_map[visual_name] = full_domain
    
    # Sort the map by visual names for consistent order in dropdown
    sorted_section_map = dict(sorted(section_map.items(), key=lambda item: item[0]))

    context = {
        'breach': breach,
        'users': users,
        'sections': sorted_section_map,  # Pass sorted map
    }
    return render(request, 'haveibeenpwned_breach.html', context)

# HAVEIBEENPWNED SECTION END

def sort_nessus_data(nessus_data):
    """
    Sorts a list of Nessus data dictionaries by risk level.
    
    Parameters:
    - nessus_data: A list of dictionaries, each representing Nessus data for an entry.
    
    Returns:
    - A list of dictionaries sorted by the defined criticality of the 'Risk' key.
    """
    risk_order = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "None": 1}
    return sorted(nessus_data, key=lambda x: risk_order.get(x.get("Risk", "None"), 0), reverse=True)
 

def clean_nessus_data(nessus_data):
    """ Cleans up the nessus data so it can be properly rendered into the template """
    # Initialize a dictionary to group data by Plugin_ID
    grouped_data = {}
    for item in nessus_data:
        # Replace spaces in keys with underscores for template compatibility
        item = {key.replace(" ", "_"): value for key, value in item.items()}
        item = {key.replace(".", "_"): value for key, value in item.items()}
        plugin_id = item["Plugin_ID"]
        
        if plugin_id not in grouped_data:
            # Initialize entry with the current item and set affected hosts to 1
            grouped_data[plugin_id] = item
            grouped_data[plugin_id]["Affected_Hosts"] = 1
        else:
            # Increment affected hosts count for existing entries
            grouped_data[plugin_id]["Affected_Hosts"] += 1
    return grouped_data


def nessus(request):
    """
    Fetches the latest Nessus result entry and sorts the data.
    """
    # Fetch the newest entry
    newest_entry = NessusData.objects.order_by('-date').first()

    if newest_entry is not None:
        # Extract scan_id and date from the newest entry
        scan_id = newest_entry.scan_id
        date = newest_entry.date.strftime('%Y-%m-%d')

        # Assuming nessus_data is stored as a JSON string, parse it
        nessus_data_raw = json.loads(newest_entry.data)

        # Clean the nessus data
        grouped_data = clean_nessus_data(nessus_data_raw)

        # Assuming sort_nessus_data is a function that sorts the nessus data
        nessus_data = sort_nessus_data(list(grouped_data.values()))
    else:
        nessus_data = []  # Use an empty list if no entry is found
        scan_id = None
        date = None

    # Pass the processed nessus_data along with scan_id and date to the context
    context = {'nessus_data': nessus_data, 'scan_id': scan_id, 'date': date}
    return render(request, 'nessus.html', context)

def nessus_plugin_details(request, plugin_id):
    """
    Fetches all vulnerable hosts for a specific vulnerability (plugin_id)
    """
    # Fetch the newest entry with scan_id == "20"
    newest_entry = NessusData.objects.filter(scan_id="20").order_by('-date').first()

    if newest_entry is not None:
        # Assuming nessus_data is stored as a JSON string, parse it
        nessus_data_raw = json.loads(newest_entry.data)

        # Clean the nessus data
        grouped_data = clean_nessus_data(nessus_data_raw)

        # Assuming sort_nessus_data is a function that sorts the nessus data
        nessus_data = sort_nessus_data(list(grouped_data.values()))

    else:
        nessus_data = []

    context = {'nessus_data': nessus_data, 'plugin_id': plugin_id}
    return render(request, 'nessus_plugin_details.html', context)

def nessus_host_details(request, hostname):
    """
    Fetches Nessus vulnerabilities for a hostname
    """
    # Fetch the newest entry with scan_id == "20"
    newest_entry = NessusData.objects.filter(scan_id="20").order_by('-date').first()

    if newest_entry is not None:
        # Assuming nessus_data is stored as a JSON string, parse it
        nessus_data_raw = json.loads(newest_entry.data)

        # Clean the nessus data
        grouped_data = clean_nessus_data(nessus_data_raw)

        # Assuming sort_nessus_data is a function that sorts the nessus data
        all_data = sort_nessus_data(list(grouped_data.values()))

        # Preprocess data to replace spaces in keys with underscores
        processed_data = [{key.replace(" ", "_"): value for key, value in item.items()} for item in all_data]

        nessus_syn_info = []
        nessus_http_info = []

        # Initialize the list for other filtered data
        filtered_data = []

        for entry in processed_data:
            if entry.get('Host') == hostname:
                if entry.get('Plugin_ID') == '11219':
                    nessus_syn_info.append(entry)
                    continue
                if entry.get("Plugin_ID") == "19506":
                    continue
                if entry.get('Plugin_ID') == "10107":
                    nessus_http_info.append(entry)
                else:
                    filtered_data.append(entry)
        filtered_data = sort_nessus_data(filtered_data)
    else:
        filtered_data = []

    context = {
        'nessus_data': filtered_data,
        'hostname': hostname,
        'nessus_syn_info': nessus_syn_info,
        'nessus_http_info': nessus_http_info,

    }
    return render(request, 'nessus_host_details.html', context)

def parse_nessus_scan_info(scan_text):
    """
    Parses nessus scan info to make it a bit more digestable.
    """
    # Define the keys in the order they appear in the scan text
    keys = [
        "Nessus version", "Nessus build", "Plugin feed version", "Scanner edition used",
        "Scanner OS", "Scanner distribution", "Scan type", "Scan name", "Scan policy used",
        "Scanner IP", "Port scanner(s)", "Port range", "Ping RTT", "Thorough tests",
        "Experimental tests", "Plugin debugging enabled", "Paranoia level", "Report verbosity",
        "Safe checks", "Optimize the test", "Credentialed checks", "Patch management checks",
        "Display superseded patches", "CGI scanning", "Web application tests", 
        "Web app tests - Test mode", "Web app tests - Try all HTTP methods", 
        "Web app tests - Maximum run time", "Web app tests - Stop at first flaw", "Max hosts",
        "Max checks", "Recv timeout", "Backports", "Allow post-scan editing",
        "Nessus Plugin Signature Checking", "Audit File Signature Checking", "Scan Start Date",
        "Scan duration", "Scan for malware"
    ]
    
    # Initialize the dictionary to hold the parsed data
    parsed_data = {}

    # Process each key
    for i, key in enumerate(keys):
        start = scan_text.find(key)
        end = None  # Default end to None

        # If this is not the last key, find the start of the next key to determine the end of the current segment
        if i + 1 < len(keys):
            end = scan_text.find(keys[i + 1])

        # Extract and trim the data for the current key
        if start != -1:
            data = scan_text[start:end].replace(key, '').strip(': ').strip()
            parsed_data[key] = data

    return parsed_data


# SOFTWARE SECTION START
def software_list(request):
    """
    Fetches and shows all software stored in the database. 
    This is an overview of all software found from Microsoft Defender.
    """
    sort_by = request.GET.get('sort', 'exposed_machines_desc')  # Default sort

    # Fetch all software entries and apply initial sorting
    software_list = Software.objects.exclude(id__contains='\n')


    # Apply sorting based on the 'sort' parameter
    if sort_by == 'exposed_machines_desc':
        software_list = software_list.order_by('-exposed_machines')
    elif sort_by == 'exposed_machines_asc':
        software_list = software_list.order_by('exposed_machines')

    # Get unique vendors for dropdown, filtering by exposed_machines > 0
    vendors = Software.objects.all().order_by('vendor').values_list('vendor', flat=True).distinct()

    # Filter by selected vendor if specified
    selected_vendor = request.GET.get('vendor')
    public_exploit_filter = request.GET.get('publicExploit', 'false') == 'true'

    if selected_vendor:
        software_list = software_list.filter(vendor=selected_vendor)
    if public_exploit_filter:
        software_list = software_list.filter(public_exploit=True)

    context = {
        'software_list': software_list,
        'vendors': vendors,
        'selected_vendor': selected_vendor,
        'current_sort': sort_by,
        'public_exploit': public_exploit_filter,

    }
    return render(request, 'software_list.html', context)


def software_list_by_software(request, software_id):
    """
    This function shows all hosts that contain a specific software.
    """
    # Fetch the specific Software instance
    software = get_object_or_404(Software, id=software_id)

    # Fetch related SoftwareHosts using the 'software_hosts' related name defined in the SoftwareHosts model
    hosts_query = SoftwareHosts.objects.filter(software=software)
    # Apply filters if specified
    selected_os_platform = request.GET.get('os_platform')
    selected_rbac_group_name = request.GET.get('rbac_group_name')

    if selected_os_platform:
        hosts_query = hosts_query.filter(os_platform=selected_os_platform)
    if selected_rbac_group_name:
        hosts_query = hosts_query.filter(rbac_group_name=selected_rbac_group_name)

    # Fetch unique values for filters
    os_platforms = hosts_query.order_by('os_platform').values_list('os_platform', flat=True).distinct()
    rbac_group_names = hosts_query.order_by('rbac_group_name').values_list('rbac_group_name', flat=True).distinct()

    context = {
        'software': software,
        'machines': hosts_query,  
        'os_platforms': os_platforms,
        'rbac_group_names': rbac_group_names,
        'selected_os_platform': selected_os_platform,
        'selected_rbac_group_name': selected_rbac_group_name,
    }
    return render(request, 'software_list_by_software.html', context)

def all_software_hosts(request):
    """
    Shows all software specifically on servers.
    """
    sort_by = request.GET.get('sort', 'host_count_desc')
    selected_vendor = request.GET.get('vendor', None)

    # Identify the ContentType for SoftwareHosts
    software_content_type = ContentType.objects.get_for_model(SoftwareHosts)

    queryset = SoftwareHosts.objects.values(
        'software__name', 'software__id', 'software__vendor'
    ).annotate(host_count=Count('host_id'))

    if selected_vendor:
        queryset = queryset.filter(software__vendor=selected_vendor)

    software_host_list = list(queryset)

    # Apply sorting
    if sort_by == 'host_count_desc':
        software_host_list.sort(key=lambda x: x['host_count'], reverse=True)
    elif sort_by == 'host_count_asc':
        software_host_list.sort(key=lambda x: x['host_count'], reverse=False)

    # Fetch comments for each software
    for software in software_host_list:
        comments = Comment.objects.filter(
            content_type=software_content_type,
            object_id=software['software__id']
        )
        software['comment'] = comments[0].content if comments.exists() else ""
        try:
            software['url'] = reverse('host_list_by_software', kwargs={'software_id': software['software__id']})
        except NoReverseMatch:
            software['url'] = None

    vendors = {entry['software__vendor'] for entry in software_host_list}

    context = {
        'software_list': software_host_list,
        'current_sort': sort_by,
        'vendors': sorted(vendors),
        'selected_vendor': selected_vendor,
    }
    return render(request, 'software_list_server.html', context)


# SOFTWARE SECTION END


def shodan_results(request):
    """
    Shows all of the results from Shodan, with filters and sorting to structure the data.
    """
    results = ShodanScanResult.objects.all()
    products = results.values_list('data__product', flat=True).distinct()
    products = [product for product in products if product]

    # Extract unique statuses from the results
    statuses = results.values_list('data__http__status', flat=True).distinct()
    statuses = [status for status in statuses if status]  # Filter out None values

    ports = results.values_list('data__port', flat=True).distinct().order_by('data__port')
    ports = [port for port in ports if port]

    selected_product = request.GET.get('product')
    if selected_product:
        # Decode URL-encoded spaces manually, though Django should handle this.
        selected_product = selected_product.replace('%20', ' ')
        results = results.filter(data__product=selected_product)

    selected_status = request.GET.get('status')
    if selected_status:
        try:
            # Attempt to convert to an integer for comparison, if applicable
            status_value = int(selected_status)
        except ValueError:
            # Handle as a string if conversion fails
            status_value = selected_status

        results = results.filter(data__http__status=status_value)
    
    selected_port = request.GET.get('port')
    if selected_port:
        try:
            port_value = int(selected_port)
            results = results.filter(data__port=port_value)
        except ValueError:
            # If port cannot be converted to int, possibly handle error or ignore the filter
            pass

    parsed_results = []
    ports = set()
    hostnames = set()

    shodan_content_type = ContentType.objects.get_for_model(ShodanScanResult)

    for result in results:
        data = result.data
        # Attempt to fetch the comment for this result
        comments = Comment.objects.filter(
            content_type=shodan_content_type,
            object_id=result.id
        )
        comment_content = comments[0].content if comments else ""  # Use the first comment's content if exists
        
        parsed_result = {
            'id': result.id,
            'ip_address': result.ip_address,
            'product': data.get('product', 'N/A'),
            'status': data.get('http', {}).get('status', 'N/A'),
            'title': data.get('http', {}).get('title', 'N/A'),
            'org': data.get('org', 'N/A'),
            'isp': data.get('isp', 'N/A'),
            'asn': data.get('asn', 'N/A'),
            'port': data.get('port', 'N/A'),
            'location': f"{data.get('location', {}).get('city', 'Unknown')}, {data.get('location', {}).get('country_name', 'Unknown')}",
            'comment_content': comment_content,
        }
        parsed_results.append(parsed_result)
        ports.add(data.get('port', 'N/A'))
        hostnames.update(set(data.get('hostnames', [])))

    stats = {
        'total_ips': results.count(),
        'unique_ports': len(ports),
        'unique_hostnames': len(hostnames),
    }

    context = {
        'results': parsed_results,
        'stats': stats,
        'products': products,
        'selected_product': selected_product,
        'statuses': statuses,
        'selected_status': selected_status,
        'ports': ports,
        'selected_port': selected_port,
    }

    return render(request, 'shodan_results.html', context)


@require_POST
def add_comment(request):
    """
    Function to add a comment on the different fields around the application.
    """
    comment_content = request.POST.get('comment_content')
    comment_type = request.POST.get('comment_type')

    if comment_type == 'subscription-device':
        # Handle comments for Device entities based on subscription and device IDs
        subscription_id = request.POST.get('subscription_id')
        device_id = request.POST.get('device_id')

        print("DEVICE: {}".format(device_id))
        print("SUBSCRIPTION: {}".format(subscription_id))

        # Fetch the device object
        device = get_object_or_404(Device, device_id=device_id, subscription__subscription_id=subscription_id)

        # Prepare the content type and object_id for the generic relation
        content_type = ContentType.objects.get_for_model(Device)
        object_id = device_id  # Use device_id as the unique identifier for the comment

    elif comment_type == 'subscription':
        # Handle comments for Subscription entities
        subscription_id = request.POST.get('subscription_id')

        # Fetch the subscription object
        subscription = get_object_or_404(Subscription, subscription_id=subscription_id)

        # Prepare the content type and object_id for the generic relation
        content_type = ContentType.objects.get_for_model(Subscription)
        object_id = subscription_id

    elif comment_type == 'software':
        # Handle comments for software entities
        content_type = ContentType.objects.get_for_model(SoftwareHosts)
        object_id = request.POST.get('result_id')

    elif comment_type == 'cve-machine':
        # Handle comments for CVE-Machine combinations
        content_type = ContentType.objects.get_for_model(MachineReference)
        object_id = request.POST.get('result_id')

    elif comment_type == 'shodan':
        # Handle comments for Shodan scan results
        content_type = ContentType.objects.get_for_model(ShodanScanResult)
        object_id = request.POST.get('result_id')

    elif comment_type == 'subscription-device-vuln':
        # Handle comments for Subscription-Device-Vulnerability combination
        subscription_id = request.POST.get('subscription_id')
        device_id = request.POST.get('device_id')
        vuln_id = request.POST.get('vuln_id')

        # Fetch the device and vulnerability objects based on the subscription, device, and vuln IDs
        device = get_object_or_404(Device, device_id=device_id, subscription__subscription_id=subscription_id)

        vuln = get_object_or_404(Vulnerability, name=vuln_id)  # Assuming the vuln_id corresponds to the CVE name
        content_type = ContentType.objects.get_for_model(MachineReference) 
        object_id = "{}-{}-{}".format(str(device_id), str(subscription_id), str(vuln_id))

    else:
        # Log or handle unsupported comment types
        print(f"Unsupported comment type: {comment_type}")
        return HttpResponseRedirect(request.META.get('HTTP_REFERER'))

    # Create or update the comment with the correct content type and object ID
    comment, created = Comment.objects.update_or_create(
        content_type=content_type,
        object_id=object_id,
        defaults={'content': comment_content}
    )

    print(f"Comment {'created' if created else 'updated'}: {comment}")
    return HttpResponseRedirect(request.META.get('HTTP_REFERER'))


@require_POST
def update_all_comments(request):
    """
    View function to update all subscription comments at once.
    """
    subscription_content_type = ContentType.objects.get_for_model(Subscription)

    # Iterate through each submitted subscription comment and update accordingly
    for key, value in request.POST.items():
        if key.startswith('comment_content_'):
            # Extract the index from the key to find the corresponding subscription_id
            index = key.split('_')[-1]
            subscription_id = request.POST.get(f'subscription_id_{index}')
            comment_content = value

            if subscription_id:
                # Fetch the subscription object to ensure it exists
                subscription = get_object_or_404(Subscription, subscription_id=subscription_id)

                # Use the content type and subscription_id for the generic relation
                content_type = subscription_content_type
                object_id = subscription.subscription_id

                # Create or update the comment for the subscription
                Comment.objects.update_or_create(
                    content_type=content_type,
                    object_id=object_id,
                    defaults={'content': comment_content}
                )

    # Redirect back to the subscriptions page after updating all comments
    return HttpResponseRedirect(request.META.get('HTTP_REFERER'))
    
# CMDB
def create_cmdb_entry(request):
    if request.method == 'POST':
        form = CMDBForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('cmdb_success')
    else:
        form = CMDBForm()
    return render(request, 'create_cmdb_entry.html', {'form': form})

def cmdb_view(request):
    cmdb_entries = CMDB.objects.all()
    return render(request, 'cmdb_view.html', {'cmdb_entries': cmdb_entries})


# TICKETS

def create_ticket(request):
    if request.method == 'POST':
        form = TicketForm(request.POST)
        if form.is_valid():
            ticket = form.save(commit=False)
            ticket.changelog = [
                {"field": "Created", "timestamp": timezone.now().isoformat()}
            ]
            ticket.save()
            return redirect('ticket_list')
    else:
        form = TicketForm()
    return render(request, 'create_ticket.html', {'form': form})

def ticket_list(request):
    tickets = Ticket.objects.all()

    for ticket in tickets:
        if ticket.changelog:
            last_changed = ticket.changelog[-1].get('timestamp', None)
            ticket.last_changed = last_changed

    return render(request, 'ticket_list.html', {'tickets': tickets})

def ticket_detail(request, ticket_id):
    ticket = get_object_or_404(Ticket, id=ticket_id)
    if request.method == 'POST':
        form = TicketForm(request.POST, instance=ticket)
        if form.is_valid():
            updated_ticket = form.save(commit=False)
            changelog = ticket.changelog or []
            # Track changes
            for field in form.changed_data:
                changelog.append({
                    "field": field,
                    "old_value": getattr(ticket, field),
                    "new_value": form.cleaned_data[field],
                    "timestamp": timezone.now().isoformat()
                })

            if 'investigation_results' in request.POST and request.POST['investigation_results'] != ticket.investigation_results:
                changelog.append({
                    "field": "investigation_results",
                    "old_value": ticket.investigation_results,
                    "new_value": request.POST['investigation_results'],
                    "timestamp": timezone.now().isoformat()
                })

            updated_ticket.investigation_results = request.POST.get('investigation_results', ticket.investigation_results)
            updated_ticket.changelog = changelog
            updated_ticket.save()
            return redirect('ticket_list')
        else:
            print("invalid_form")
    else:
        form = TicketForm(instance=ticket)
    return render(request, 'ticket_detail.html', {'form': form, 'ticket': ticket})

def toggle_ticket_status(request, ticket_id):
    ticket = get_object_or_404(Ticket, id=ticket_id)
    old_status = ticket.status
    if ticket.status == 'Closed':
        ticket.status = 'Open'
    else:
        ticket.status = 'Closed'
    ticket.changelog.append({
        "field": "status",
        "old_value": old_status,
        "new_value": ticket.status,
        "timestamp": timezone.now().isoformat()
    })
    ticket.save()
    return redirect('ticket_detail', ticket_id=ticket_id)

def delete_ticket(request, ticket_id):
    ticket = get_object_or_404(Ticket, id=ticket_id)
    ticket.delete()
    return redirect('ticket_list')


def upload_public_ip_csv(request):
    if request.method == 'POST':
        form = UploadIPCSVForm(request.POST, request.FILES)
        if form.is_valid():
            file = request.FILES['file']
            try:
                decoded_file = file.read().decode('utf-8').splitlines()
            except UnicodeDecodeError:
                try:
                    file.seek(0)  # Reset file pointer to the beginning
                    decoded_file = file.read().decode('latin-1').splitlines()
                except UnicodeDecodeError:
                    return render(request, 'upload_csv.html', {
                        'form': form,
                        'error': 'File encoding not supported. Please upload a file with UTF-8 or Latin-1 encoding.'
                    })
            
            reader = csv.DictReader(decoded_file)

            for row in reader:
                # Ensure all keys are in uppercase, strip any leading/trailing spaces
                row = {key.strip().upper(): value for key, value in row.items()}
                PublicIP.objects.update_or_create(
                    name=row.get('NAME', ''),
                    ip_address=row.get('IP ADDRESS', ''),
                    defaults={
                        'resource_group': row.get('RESOURCE GROUP', ''),
                        'location': row.get('LOCATION', ''),
                        'subscription': row.get('SUBSCRIPTION', ''),
                        'dns_name': row.get('DNS NAME', ''),
                        'subscription_id': row.get('SUBSCRIPTION ID', ''),
                        'associated_to': row.get('ASSOCIATED TO', '')
                    }
                )
            return redirect('home')
        else:
            print("Form is not valid")
    else:
        form = UploadIPCSVForm()
    return render(request, 'upload_public_ip.html', {'form': form})

def public_ip_list(request):
    resource_group = request.GET.get('resource_group')
    location = request.GET.get('location')
    subscription = request.GET.get('subscription')

    public_ips = PublicIP.objects.all().order_by('ip_address')

    if resource_group:
        public_ips = public_ips.filter(resource_group=resource_group)
    if location:
        public_ips = public_ips.filter(location=location)
    if subscription:
        public_ips = public_ips.filter(subscription=subscription)

    # Get distinct values for the filters based on the filtered public_ips queryset and sort them alphabetically
    resource_groups = PublicIP.objects.filter(location__in=public_ips.values('location')).values_list('resource_group', flat=True).distinct().order_by('resource_group')
    locations = PublicIP.objects.filter(subscription__in=public_ips.values('subscription')).values_list('location', flat=True).distinct().order_by('location')
    subscriptions = PublicIP.objects.filter(resource_group__in=public_ips.values('resource_group')).values_list('subscription', flat=True).distinct().order_by('subscription')

    context = {
        'public_ips': public_ips,
        'resource_groups': resource_groups,
        'locations': locations,
        'subscriptions': subscriptions,
        'selected_resource_group': resource_group,
        'selected_location': location,
        'selected_subscription': subscription,
    }

    return render(request, 'public_ip_list.html', context)


def device_list(request):
    devices = Device.objects.all()  # Fetch all devices from the database
    device_length = len(devices)
    return render(request, 'device_list.html', {'devices': devices, 'count':device_length})

def devices_in_subscription(request, subscription_id):
    """
    Optimized view function to show all devices within a specific subscription
    and provide statistics on vulnerabilities per device, including comments and total statistics.
    Additionally, it provides the count of devices per resource group.
    """
    # Fetch the subscription object
    subscription = get_object_or_404(Subscription, subscription_id=subscription_id)

    # Get today's date
    today = timezone.now().date()

    # Get ContentType for Device model for generic relation in Comment
    device_content_type = ContentType.objects.get_for_model(Device)

    # Fetch all devices related to the subscription with prefetched comments and machine references
    devices = Device.objects.filter(subscription=subscription).prefetch_related(
        Prefetch(
            'comment_set',
            queryset=Comment.objects.filter(content_type=device_content_type).order_by('-created_at'),
            to_attr='prefetched_comments'
        ),
        Prefetch(
            'machine_references',
            queryset=MachineReference.objects.filter(last_updated__date=today).select_related('vulnerability'),
            to_attr='prefetched_machine_references'
        )
    )

    # Initialize total vulnerabilities count and dictionary for severity statistics
    total_vulnerabilities = 0
    severity_stats_dict = defaultdict(int)
    device_vulnerability_stats = []

    for device in devices:
        # Use prefetched machine references
        vuln_data = device.prefetched_machine_references

        if vuln_data:
            vuln_count = len(vuln_data)
            total_vulnerabilities += vuln_count
        else:
            vuln_count = "N/A"

        # Use prefetched comments
        comments = device.prefetched_comments
        latest_comment = comments[0].content if comments else ""

        # Append the device with its vulnerability count and the latest comment
        device_vulnerability_stats.append({
            'device': device,
            'vuln_count': vuln_count,
            'latest_comment': latest_comment,
        })

        # Calculate severity statistics
        for mr in vuln_data:
            severity = mr.vulnerability.severity
            severity_stats_dict[severity] += 1

    # Fetch resource groups with device counts in one query
    resource_groups = ResourceGroup.objects.filter(subscription=subscription).annotate(
        device_count=Count('devices')
    ).filter(device_count__gt=0)

    # Build resource group device count dictionary
    resource_group_device_count = {rg.name: rg.device_count for rg in resource_groups}

    context = {
        'subscription': subscription,
        'devices': devices,
        'device_count': devices.count(),
        'device_vulnerability_stats': device_vulnerability_stats,
        'total_vulnerabilities': total_vulnerabilities,
        'severity_stats': json.dumps(severity_stats_dict),
        'resource_group_device_stats': json.dumps(resource_group_device_count),
    }

    return render(request, 'subscription_devices.html', context)




def devices_in_resource_group(request, resource_group_name):
    """
    View function to show all devices within a specific subscription
    and provide statistics on vulnerabilities per device, including comments and total statistics.
    """
    # Fetch the subscription object
    resource_group = get_object_or_404(ResourceGroup, name=resource_group_name)

    # Fetch all devices related to the subscription
    devices = Device.objects.filter(resource_group=resource_group)

    # Get today's dated
    today = timezone.now().date()

    # List to hold devices with their vulnerability count and comments
    device_vulnerability_stats = []

    # Get ContentType for Device model for generic relation in Comment
    device_content_type = ContentType.objects.get_for_model(Device)

    # Initialize total vulnerabilities count and dictionary for severity statistics
    total_vulnerabilities = 0
    severity_stats_dict = {}

    for device in devices:
        # Fetch MachineReference objects for the current device
        vuln_data = MachineReference.objects.filter(computer_dns_name__icontains=device.display_name)

        if vuln_data.filter(last_updated__date=today).exists():
            # If data exists for today, use local data and count vulnerabilities
            vuln_count = vuln_data.count()
            total_vulnerabilities += vuln_count
        else:
            vuln_count = 0
        # Generate unique identifier for the device to fetch comments
        unique_id = device.device_id

        # Fetch comments for the device
        comments = Comment.objects.filter(
            content_type=device_content_type,
            object_id=unique_id
        ).order_by('-created_at')

        # Check if there are any comments and retrieve the latest one if exists
        latest_comment = comments[0].content if comments.exists() else ""

        # Append the device with its vulnerability count and the latest comment
        device_vulnerability_stats.append({
            'device': device,
            'vuln_count': vuln_count,
            'latest_comment': latest_comment,
        })

        # Fetch severity statistics for the vulnerabilities associated with this device
        severity_statistics = vuln_data.values('vulnerability__severity').annotate(total_count=Count('vulnerability__severity'))

        # Combine all entries of each severity level into a single dictionary element
        for entry in severity_statistics:
            severity = entry['vulnerability__severity']
            total_count = entry['total_count']
            if severity in severity_stats_dict:
                severity_stats_dict[severity] += total_count
            else:
                severity_stats_dict[severity] = total_count

    context = {
        'resource_group': resource_group,
        'devices': devices,
        'device_count': devices.count(),
        'device_vulnerability_stats': device_vulnerability_stats,
        'total_vulnerabilities': total_vulnerabilities,
        'severity_stats': json.dumps(severity_stats_dict),
        'subscription': resource_group.subscription,
    }
    
    return render(request, 'resource_group_devices.html', context)


def fetch_machines_by_severity(request, subscription_id, severity):
    """
    AJAX view to fetch machines (MachineReferences) with a given severity for a specific subscription.
    """
    # Fetch the subscription object
    subscription = get_object_or_404(Subscription, subscription_id=subscription_id)
    
    # Fetch all devices related to the subscription
    devices = Device.objects.filter(subscription=subscription)
    
    # Fetch all MachineReference objects with the selected severity that are part of the subscription's devices
    machine_references = MachineReference.objects.filter(
        device__in=devices,
        vulnerability__severity=severity
    ).values('machine_id', 'computer_dns_name', 'os_platform', 'detection_time')

    # Return the results as a JSON response
    return JsonResponse(list(machine_references), safe=False)

def display_all_subscriptions(request):
    """
    View function to display all subscriptions with their respective
    number of vulnerabilities, resource groups, and latest comments.
    """
    # Fetch all subscriptions
    subscriptions = Subscription.objects.all()

    # Prepare a list to hold subscription details
    subscription_details = []

    # Get the content type for Subscription model to fetch related comments
    subscription_content_type = ContentType.objects.get_for_model(Subscription)

    for subscription in subscriptions:
        # Fetch the vulnerability count from the subscription's field
        vulnerability_count = subscription.vulnerability_count

        # Calculate the total vulnerability count by summing all severity levels
        total_vulnerability_count = (
            vulnerability_count.get('Critical', 0) +
            vulnerability_count.get('High', 0) +
            vulnerability_count.get('Medium', 0) +
            vulnerability_count.get('Low', 0)
        )

        # Count the number of resource groups related to the subscription
        resource_group_count = ResourceGroup.objects.filter(subscription=subscription).count()

        # Fetch the latest comment for the subscription
        latest_comment = Comment.objects.filter(
            content_type=subscription_content_type,
            object_id=subscription.subscription_id
        ).order_by('-created_at').first()

        # Add the subscription details to the list, including the total vulnerability count and the latest comment
        subscription_details.append({
            'subscription': subscription,
            'vulnerability_count': vulnerability_count,
            'total_vulnerability_count': total_vulnerability_count,
            'resource_group_count': resource_group_count,
            'latest_comment': latest_comment.content if latest_comment else ''  # Add latest comment content if exists
        })

    # Sort subscription details by total_vulnerability_count in descending order
    subscription_details = sorted(subscription_details, key=lambda x: x['total_vulnerability_count'], reverse=True)

    context = {
        'subscription_details': subscription_details
    }

    return render(request, 'all_subscriptions.html', context)

def critical_vulnerabilities_view(request):
    # Fetch all critical vulnerabilities
    critical_vulnerabilities = Vulnerability.objects.filter(severity='Critical')

    # List to hold vulnerability details along with the count of machine references
    vulnerabilities_list = []

    # Iterate over each critical vulnerability and get the count of its references in MachineReference
    for vulnerability in critical_vulnerabilities:
        machine_count = MachineReference.objects.filter(vulnerability=vulnerability).count()

        # Append the vulnerability details along with the machine count to the list
        vulnerabilities_list.append({
            'vulnerability': vulnerability,
            'machine_count': machine_count
        })

    # Render the vulnerabilities and their machine counts in a template
    context = {
        'vulnerabilities_list': vulnerabilities_list
    }
    
    return render(request, 'critical_vulns_test.html', context)