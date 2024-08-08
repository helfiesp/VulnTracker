from django import forms
from .models import Keyword, Blacklist, CMDB, Ticket
from tinymce.widgets import TinyMCE

class KeywordUploadForm(forms.Form):
    file = forms.FileField()
    
class KeywordForm(forms.ModelForm):
    class Meta:
        model = Keyword
        fields = ['word']
    
class BlacklistForm(forms.ModelForm):
    class Meta:
        model = Blacklist
        fields = ['word']

class CMDBForm(forms.ModelForm):
    class Meta:
        model = CMDB
        fields = [
            'hostname', 'entra_host_id', 'subscription_name', 'subscription_id',
            'host_type', 'ip_address', 'internet_exposed', 'department', 'department_software'
        ]


class TicketForm(forms.ModelForm):
    description = forms.CharField(widget=TinyMCE())
    
    class Meta:
        model = Ticket
        fields = ['title', 'description', 'severity', 'ticket_type']


class UploadIPCSVForm(forms.Form):
    file = forms.FileField()