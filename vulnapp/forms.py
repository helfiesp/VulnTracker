from django import forms
from .models import Keyword, Blacklist

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