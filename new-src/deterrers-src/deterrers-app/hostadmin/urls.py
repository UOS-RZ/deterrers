from django.urls import path, re_path
from . import views

urlpatterns = [
    re_path(r'^host/(?P<ip>[0-9]{1,3}(_[0-9]{1,3}){3})/$', views.host_detail_view, name='host_detail'),
    re_path(r'^host/(?P<ip>[0-9]{1,3}(_[0-9]{1,3}){3})/update/$', views.update_host_detail, name='update_host_detail'),
    re_path(r'^host/(?P<ip>[0-9]{1,3}(_[0-9]{1,3}){3})/register/$', views.register_host, name='register_host'),
    re_path(r'^host/(?P<ip>[0-9]{1,3}(_[0-9]{1,3}){3})/scan/$', views.scan_host, name='scan_host'),
    path('hosts/', views.hosts_list_view, name='hosts_list'),
    path('overview/', views.hostadmin_overview_view, name='hostadmin_overview'),
    path('', views.about_view, name='about'),
    path('greenbone-registration-alert/', views.v_scanner_registration_alert, name='v_scanner_registration_alert'),
    path('greenbone-scan-alert/', views.v_scanner_scan_alert, name='v_scanner_scan_alert'),
]
