from django.urls import path, re_path, register_converter
from . import views

class IPPathConverter:
    regex = '[0-9]{1,3}(_[0-9]{1,3}){3}'
    def to_python(self, value):
        # convert value to its corresponding python datatype
        return value.replace('_', '.')
    def to_url(self, value):
        # convert the value to str data 
        return value.replace('.', '_')

register_converter(IPPathConverter, 'esc_ip')

urlpatterns = [
    path('host/<esc_ip:ip>/', views.host_detail_view, name='host_detail'),
    path('host/<esc_ip:ip>/rule/delete/<uuid:rule_id>/', views.delete_host_rule, name='delete_rule'),
    path('host/<esc_ip:ip>/update/', views.update_host_detail, name='update_host_detail'),
    path('host/<esc_ip:ip>/register/', views.register_host, name='register_host'),
    path('host/<esc_ip:ip>/scan/', views.scan_host, name='scan_host'),
    path('hosts/', views.hosts_list_view, name='hosts_list'),
    path('overview/', views.hostadmin_overview_view, name='hostadmin_overview'),
    path('', views.about_view, name='about'),
    path('greenbone-registration-alert/', views.v_scanner_registration_alert, name='v_scanner_registration_alert'),
    path('greenbone-scan-alert/', views.v_scanner_scan_alert, name='v_scanner_scan_alert'),
    path('greenbone-periodic-alert/', views.v_scanner_periodic_alert, name='v_scanner_periodic_alert'),
]

