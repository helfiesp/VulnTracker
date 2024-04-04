from django.db import models
import json
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType

class Keyword(models.Model):
    word = models.CharField(max_length=255, unique=True)

    def __str__(self):
        return self.word

class Blacklist(models.Model):
    word = models.CharField(max_length=255, unique=True)

    def __str__(self):
        return self.word
        
class CVE(models.Model):
    cve_id = models.CharField(max_length=50, unique=True)
    source_identifier = models.CharField(max_length=100)
    published_date = models.DateTimeField()
    last_modified_date = models.DateTimeField()
    vuln_status = models.CharField(max_length=50)
    description = models.TextField()
    keywords = models.TextField(null=True, blank=True)
    cvss_score = models.FloatField(null=True, blank=True)
    cvss_vector = models.CharField(max_length=100, null=True, blank=True)
    cvss_severity = models.CharField(max_length=50, null=True, blank=True)
    cwe = models.CharField(max_length=50, null=True, blank=True)
    references = models.TextField()
    known_exploited = models.BooleanField(default=False)


    def __str__(self):
        return self.cve_id
        
class Vulnerability(models.Model):
    id = models.CharField(max_length=255, primary_key=True)
    name = models.CharField(max_length=255)
    description = models.TextField()
    severity = models.CharField(max_length=50)
    cvssV3 = models.FloatField(null=True, blank=True)
    cvssVector = models.CharField(max_length=255, blank=True, null=True)
    exposedMachines = models.IntegerField(default=0)
    publishedOn = models.DateField()
    updatedOn = models.DateField()
    firstDetected = models.DateField(null=True, blank=True)
    publicExploit = models.BooleanField(default=False)
    exploitVerified = models.BooleanField(default=False)
    exploitInKit = models.BooleanField(default=False)
    exploitTypes = models.JSONField(default=list)
    exploitUris = models.JSONField(default=list)
    cveSupportability = models.CharField(max_length=100)

    def __str__(self):
        return self.name

class MachineReference(models.Model):
    vulnerability = models.ForeignKey(Vulnerability, on_delete=models.CASCADE, related_name='machine_references')
    machine_id = models.CharField(max_length=255)
    computer_dns_name = models.CharField(max_length=255, null=True, blank=True)
    os_platform = models.CharField(max_length=100, null=True, blank=True)
    rbac_group_name = models.CharField(max_length=255, null=True, blank=True)
    rbac_group_id = models.IntegerField(null=True, blank=True)
    detection_time = models.DateTimeField(null=True, blank=True)
    last_updated = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('vulnerability', 'machine_id')

    def __str__(self):
        return self.computer_dns_name

class HaveIBeenPwnedBreaches(models.Model):
    name = models.CharField(max_length=100)
    title = models.CharField(max_length=100)
    domain = models.CharField(max_length=100)
    breach_date = models.DateField()
    added_date = models.DateTimeField()
    modified_date = models.DateTimeField()
    pwn_count = models.BigIntegerField()
    description = models.TextField()
    logo_path = models.URLField()
    data_classes = models.TextField() 
    is_verified = models.BooleanField()
    is_fabricated = models.BooleanField()
    is_sensitive = models.BooleanField()
    is_retired = models.BooleanField()
    is_spam_list = models.BooleanField()
    is_malware = models.BooleanField()
    is_subscription_free = models.BooleanField()

    def set_data_classes(self, data):
        self.data_classes = json.dumps(data)

    def get_data_classes(self):
        return json.loads(self.data_classes)

class HaveIBeenPwnedBreachedAccounts(models.Model):
    email_address = models.CharField(max_length=100)
    breached_sites = models.TextField()
    comment = models.TextField(default=None, null=True)


class ExploitedVulnerability(models.Model):
    cve_id = models.CharField(max_length=20, primary_key=True)
    vendor_project = models.CharField(max_length=255)
    product = models.CharField(max_length=255)
    vulnerability_name = models.CharField(max_length=255)
    date_added = models.DateField()
    short_description = models.TextField()
    required_action = models.TextField()
    due_date = models.DateField()
    known_ransomware_campaign_use = models.CharField(max_length=255)

    def __str__(self):
        return self.cve_id


class Software(models.Model):
    id = models.CharField(max_length=255, primary_key=True)
    name = models.CharField(max_length=255)
    vendor = models.CharField(max_length=255)
    weaknesses = models.IntegerField()
    public_exploit = models.BooleanField()
    active_alert = models.BooleanField()
    exposed_machines = models.IntegerField()
    impact_score = models.FloatField()

    def __str__(self):
        return self.name

class SoftwareHosts(models.Model):
    software = models.ForeignKey(Software, on_delete=models.CASCADE, related_name='software_hosts')
    host_id = models.CharField(max_length=255)  # No longer the primary key
    computer_dns_name = models.CharField(max_length=255)
    os_platform = models.CharField(max_length=255)
    rbac_group_name = models.CharField(max_length=255, blank=True, null=True)
    
    # If you still need to ensure that each software/host_id pair is unique, you can add this:
    class Meta:
        unique_together = ('software', 'host_id')

    def __str__(self):
        return self.computer_dns_name


class ScanStatus(models.Model):
    scan_type = models.CharField(max_length=200)
    status = models.CharField(max_length=10, choices=(('success', 'Success'), ('error', 'Error')))
    completed_at = models.DateTimeField(auto_now_add=True)
    details = models.TextField(blank=True, null=True)  # JSON string to store variable data
    error_message = models.TextField(blank=True, null=True)

    def set_details(self, data):
        """
        Store a dictionary in the details field as a JSON string.
        """
        if isinstance(data, dict):
            self.details = json.dumps(data)
        else:
            raise ValueError("Only dictionaries are allowed for the details field.")

    def get_details(self):
        """
        Retrieve the details field data as a dictionary.
        """
        if self.details:
            return json.loads(self.details)
        else:
            return {}

    def save(self, *args, **kwargs):
        """
        Overwrite the save method to ensure details are always stored as a JSON string.
        """
        if isinstance(self.details, dict):
            self.details = json.dumps(self.details)
        super(ScanStatus, self).save(*args, **kwargs)

class ShodanScanResult(models.Model):
    ip_address = models.CharField(max_length=15, unique=True)
    data = models.JSONField()  # Stores the JSON data returned by Shodan
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.ip_address

class NessusData(models.Model):
    data = models.TextField()
    date = models.DateTimeField(auto_now_add=True) 
    scan_id = models.CharField(max_length=255)


class Comment(models.Model):
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # Fields for generic relation
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)
    object_id = models.CharField(max_length=255) 
    content_object = GenericForeignKey('content_type', 'object_id')

    def __str__(self):
        return f"Comment on {self.content_type.model} - {self.created_at.strftime('%Y-%m-%d %H:%M')}"

class HostToBSS(models.Model):
    host = models.CharField(max_length=255)
    bss = models.TextField()