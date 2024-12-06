from django.db import models
import json

# Create your models here.

class Vulnerability(models.Model):
    uuid = models.CharField(max_length= 128)
    host_ipv4 = models.CharField(max_length=32)
    port = models.CharField(max_length=16)
    proto = models.TextField()
    hostname = models.TextField()
    nvt_name = models.TextField()
    nvt_oid = models.TextField()
    qod = models.IntegerField()
    cvss_version = models.IntegerField()
    cvss_base_score = models.FloatField()
    cvss_base_vector = models.TextField()
    description = models.TextField()
    refs = models.TextField() #json
    overrides = models.TextField() #json
    date_time = models.TextField()
    task_id = models.CharField(max_length= 128)
    report_id = models.CharField(max_length= 128)

class Scan_report(models.Model):
    report_xml = models.TextField()
    report_id = models.IntegerField(primary_key=True)

class Host_Silenced_Vulnerabilities(models.Model):
    entity_id = models.IntegerField(primary_key=True)
    uuids = models.TextField #json
    host_ipv4 = models.CharField(max_length=128)