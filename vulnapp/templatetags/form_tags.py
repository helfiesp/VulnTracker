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
    Truncate text at the nearest punctuation mark after the specified length,
    without removing any characters.
    """
    if len(text) <= length:
        return text

    # Attempt to truncate at the nearest punctuation mark within the length limit
    punctuation_match = re.search(r'[.!?]\s', text[length:])
    if punctuation_match:
        punctuation_index = length + punctuation_match.end()
        return text[:punctuation_index]

    # If no punctuation is found, truncate to the nearest word within the length limit
    truncated_text = text[:length]
    last_space = truncated_text.rfind(' ')
    if last_space > -1:
        truncated_text = truncated_text[:last_space]

    return truncated_text + '...'