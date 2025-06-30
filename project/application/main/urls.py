from django.urls import path, register_converter
from . import views
from .api import api_views


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
    path('',
         views.hosts_list_view,
         name='main_landing'),
    path('about/',
         views.about_view,
         name='about'),
    path('init/',
         views.hostadmin_init_view,
         name='hostadmin_init'),
    path('hosts/',
         views.hosts_list_view,
         name='hosts_list'),
    path('host/<esc_ip:ipv4>/',
         views.host_detail_view,
         name='host_detail'),
    path('host/<esc_ip:ipv4>/detail',
         views.host_detail_view,
         name='host_detail'),
    path('host/<esc_ip:ipv4>/detail/<str:tab>',
         views.host_detail_view,
         name='host_detail'),
    path('host/<esc_ip:ipv4>/update/general',
         views.update_host_detail,
         name='update_host_detail'),
    path('host/<esc_ip:ipv4>/update/host_firewall',
         views.update_host_firewall,
         name='update_host_firewall'),
    path('host/<esc_ip:ipv4>/register/',
         views.register_host,
         name='register_host'),
    path('hosts/delete_scan_object',
         views.delete_scan_object,
         name='delete_scan_object'),  
    path('host/<esc_ip:ipv4>/scan/',
         views.scan_host,
         name='scan_host'),
    path('host/<esc_ip:ipv4>/block/',
         views.block_host,
         name='block_host'),
    path('host/<esc_ip:ipv4>/get-fw-config/',
         views.get_fw_config,
         name='get_fw_config'),
    path('host/<esc_ip:ipv4>/rule/delete/<uuid:rule_id>/',
         views.delete_host_rule,
         name='delete_rule'),
    path('host/<esc_ip:ipv4>/remove/',
         views.remove_host,
         name='remove_host'),
    # V-scanner alerts
    path('scanner/alert/registration/',
         views.scanner_registration_alert,
         name='scanner_registration_alert'),
    path('scanner/alert/scan/',
         views.scanner_scan_alert,
         name='scanner_scan_alert'),
    path('scanner/alert/periodic/',
         views.scanner_periodic_alert,
         name='scanner_periodic_alert'),
    # API views
    path('api/schema/',
         views.api_schema,
         name='api_schema'),
    path('api/hosts/',
         api_views.hosts),
    path('api/host/',
         api_views.host),
    path('api/action/',
         api_views.action),
]
