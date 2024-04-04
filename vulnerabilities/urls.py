"""
URL configuration for vulnerabilities project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from vulnapp import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.index, name='home'),
    path('cve/keywords/', views.keyword_view, name='keywords'),
    path('cve/blacklist/', views.blacklist_view, name='blacklist'),
    path('cve/delete/<str:model_name>/<int:word_id>/', views.delete_word, name='delete_word'),

    path('defender/vulnerabilities', views.defender_vulnerabilities, name='defender_vulnerabilities'),
    path('defender/vulnerabilities/<str:cve_id>/machines/', views.machine_list, name='machine-list'),
    path('defender/machines/<str:computer_dns_name>/cves/', views.cve_list_for_machine, name='cve-list-for-machine'),

    path('haveibeenpwned', views.haveibeenpwned_breaches, name='haveibeenpwned'),
    path('haveibeenpwned/<str:breach_name>/', views.breached_users_list, name='breached_users_list'),
    path('haveibeenpwned/user/<str:email>/', views.get_breaches_for_user, name='get_breaches_for_user'),

    path('software_list/', views.software_list, name='software_list'),
    path('software_list/server', views.all_software_hosts, name='software_list_server'),
    path('software_list/software/<path:software_id>/', views.software_list_by_software, name='host_list_by_software'),


    path('nessus', views.nessus, name='nessus'),
    path('nessus/plugin/<str:plugin_id>/', views.nessus_plugin_details, name='nessus_plugin_details'),
    path('nessus/host/<str:hostname>/', views.nessus_host_details, name='nessus_host_details'),


    path('shodan', views.shodan_results, name='shodan'),
    path('scan/status', views.scan_status, name='scan_status'),

    path('add_comment/', views.add_comment, name='add_comment'),


]
