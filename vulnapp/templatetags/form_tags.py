from django import template
import re

register = template.Library()

@register.filter
def get_criticality_level(cve):
    if cve.cvss_score >= 9.0:
        return 'Critical'
    elif 7.5 <= cve.cvss_score < 9.0:
        return 'High'
    elif 5.0 <= cve.cvss_score < 7.5:
        return 'Medium'
    elif 2.5 <= cve.cvss_score < 5.0:
        return 'Low'
    else:
        return 'N/A'

@register.filter
def get_defender_criticality_level(cvssV3):
    try:
        cvssV3 = float(cvssV3)
        if cvssV3 >= 9.0:
            return 'Critical'
        elif 7.5 <= cve.cvss_score < 9.0:
            return 'High'
        elif 5.0 <= cve.cvss_score < 7.5:
            return 'Medium'
        elif 2.5 <= cve.cvss_score < 5.0:
            return 'Low'
        else:
            return 'N/A'
    except ValueError:
        return "N/A"



@register.filter
def smart_truncate(text, length=300):
    """
    Truncate text at the nearest punctuation mark after the specified length.
    """
    if len(text) <= length:
        return text
    # Truncate the text to the nearest word first
    truncated_text = text[:length].rsplit(' ', 1)[0]
    # Find the nearest punctuation mark after the truncated text
    remainder_text = text[len(truncated_text):]
    match = re.search(r'[.!?]\s', remainder_text)
    if match:
        punctuation_index = len(truncated_text) + match.start() + 1
        return text[:punctuation_index]
    return truncated_text + '...'