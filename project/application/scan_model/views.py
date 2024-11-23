from django.shortcuts import HttpResponse
from scan_model.models import Scan, Host_scan

# Create your views here.
def testview(request):
    g = Host_scan.objects.all()
    s = g[0].last_scan.report_html 
    return HttpResponse(s,200)