from django.db import models

# Create your models here.

class Scan(models.Model):
    report_html = models.TextField()
    previous_scan = models.ForeignKey('self',models.SET_NULL,null=True)

class Host_scan(models.Model):
    entity_id = models.IntegerField()
    last_scan = models.ForeignKey(Scan,on_delete=models.SET_NULL,null=True)
    

