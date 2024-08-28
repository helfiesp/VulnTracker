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
    Truncate the text at the nearest punctuation mark after the specified length,
    without removing any characters.
    """
    if len(text) <= length:
        return text

    # Find the last full sentence within the given length
    truncated_text = text[:length]

    # Find the last punctuation within the truncated text
    last_punctuation = re.search(r'[.!?]', truncated_text[::-1])

    if last_punctuation:
        # Truncate at the last punctuation found
        punctuation_position = length - last_punctuation.start()
        return text[:punctuation_position] + '...'

    # If no punctuation is found, return the text as is up to the length limit
    return truncated_text + '...'

@register.filter
def filter_device_info(text, device_info):
    device_info = device_info.split(" (")[0]
    return device_info