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
    path('add_comment/', views.add_comment, name='add_comment'),

    path('create_cmdb_entry/', views.create_cmdb_entry, name='create_cmdb_entry'),
    path('cmdb/', views.cmdb_view, name='cmdb'),
    path('upload_public_ip_csv/', views.upload_public_ip_csv, name='upload_public_ip_csv'),
    path('create_ticket/', views.create_ticket, name='create_ticket'),
    path('ticket_list/', views.ticket_list, name='ticket_list'),
    path('ticket_detail/<int:ticket_id>/', views.ticket_detail, name='ticket_detail'),
    path('toggle_ticket_status/<int:ticket_id>/', views.toggle_ticket_status, name='toggle_ticket_status'),
    path('ticket_detail/<int:ticket_id>/delete', views.delete_ticket, name='delete_ticket'),
    path('public_ip_list/', views.public_ip_list, name='public_ip_list'),


]
