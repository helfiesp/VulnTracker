from django import template

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
    # Find the nearest punctuation mark after the given length
    truncated_text = text[:length]
    match = re.search(r'[.!?]\s', text[length:])
    if match:
        punctuation_index = length + match.start() + 1
        return text[:punctuation_index]
    return truncated_text + '...'