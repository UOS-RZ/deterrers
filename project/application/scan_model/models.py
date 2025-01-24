from django.db import models
import json
from django.db.models.signals import post_save
import logging

# Create your models here.

class Vulnerability(models.Model):
    uuid = models.CharField(max_length= 128)
    vulnerability_name = models.TextField()
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
    report_id = models.CharField(max_length= 128,primary_key=True)

class Host_Silenced_Vulnerabilities(models.Model):
    entity_id = models.IntegerField(primary_key=True)
    uuids = models.TextField #json
    host_ipv4 = models.CharField(max_length=128)

# logs just saved Vulnerability for debugging purpose
def print_saved_instance(sender,instance, **kwargs):
    logger = logging.getLogger("post_save_logger")
    logger.info("uuid: %s ,report_id: %s , nvt_oid: %s , name: %s",instance.uuid,instance.report_id,instance.nvt_oid,instance.vulnerability_name)

post_save.connect(print_saved_instance,sender=Vulnerability)