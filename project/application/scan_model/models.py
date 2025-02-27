from django.db import models
from user.models import MyUser

# Create your models here.

class Vulnerability(models.Model):
    uuid = models.CharField(max_length= 128)
    vulnerability_name = models.TextField(blank=True)
    host_ipv4 = models.GenericIPAddressField(protocol='IPv4')
    port = models.CharField(max_length=16,blank=True)
    proto = models.TextField(blank=True)
    hostname = models.TextField(blank=True)
    nvt_name = models.TextField(blank=True)
    nvt_oid = models.TextField(blank=True)
    qod = models.IntegerField(blank=True)
    cvss_version = models.IntegerField(blank=True)
    cvss_base_score = models.FloatField(blank=True)
    cvss_base_vector = models.TextField(blank=True)
    description = models.TextField(blank=True)
    refs = models.TextField(blank=True) #json
    overrides = models.TextField(blank=True) #json
    date_time = models.DateTimeField(blank=True)
    task_id = models.CharField(max_length= 128,blank=True)
    report_id = models.CharField(max_length= 128,blank=True)
    is_silenced = models.BooleanField()


class Scan_report(models.Model):
    report_xml = models.TextField(blank=True)
    report_id = models.CharField(max_length=128, primary_key=True)


class Host_Silenced_Vulnerabilities(models.Model):
    nvt_oid = models.TextField()
    host_ipv4 = models.GenericIPAddressField(protocol='IPv4')
    date_time = models.DateTimeField(blank=True)
    user = models.CharField(max_length=150)
    is_active = models.BooleanField()
