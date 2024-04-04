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
        return 'Informational'

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
            return 'Informational'
    except ValueError:
        return "Informational"

