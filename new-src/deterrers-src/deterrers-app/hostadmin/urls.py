from django.urls import path, register_converter
from rest_framework.schemas import get_schema_view
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
    path('', views.about_view, name='about'),
    path('init/', views.hostadmin_init_view, name='hostadmin_init'),
    path('hosts/', views.hosts_list_view, name='hosts_list'),
    path('host/<esc_ip:ipv4>/', views.host_detail_view, name='host_detail'),
    path('host/<esc_ip:ipv4>/rule/delete/<uuid:rule_id>/', views.delete_host_rule, name='delete_rule'),
    path('host/<esc_ip:ipv4>/update/', views.update_host_detail, name='update_host_detail'),
    path('host/<esc_ip:ipv4>/register/', views.register_host, name='register_host'),
    path('host/<esc_ip:ipv4>/scan/', views.scan_host, name='scan_host'),
    path('host/<esc_ip:ipv4>/block/', views.block_host, name='block_host'),
    path('host/<esc_ip:ipv4>/get-fw-config/', views.get_fw_config, name='get_fw_config'),
    path('greenbone-registration-alert/', views.v_scanner_registration_alert, name='v_scanner_registration_alert'),
    path('greenbone-scan-alert/', views.v_scanner_scan_alert, name='v_scanner_scan_alert'),
    path('greenbone-periodic-alert/', views.v_scanner_periodic_alert, name='v_scanner_periodic_alert'),
    # API views
    path('api/hosts/', api_views.hosts),
    path('api/host/', api_views.host),
    path('api/action/', api_views.action),
    path('api/openapi-schema', get_schema_view(
        title="DETERRERS",
        description="API Prototype",
        version="0.0.1"
    ), name='openapi-schema'),
]
