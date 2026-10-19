from django.contrib.admin.apps import AdminConfig


class MetricsAdminConfig(AdminConfig):
    default_site = 'vulnerability_mgmt.admin.MetricsAdminSite'
