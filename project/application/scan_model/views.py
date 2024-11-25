from django.http import Http404,HttpResponse
from scan_model.models import Scan, Host_scan
from django.core.exceptions import ObjectDoesNotExist

# Create your views here.
def testview(request):
    g = Host_scan.objects.all()
    s = g[0].last_scan.report_html 
    return HttpResponse(s,200)

# def testview(request):
#     try:
#         host = Host_scan.objects.get(entity_id = )
#     except ObjectDoesNotExist:
#         new_host = Host_scan( entity_id = )
#         new_host.save()
#         host = Host_scan.objects.get(entity_id = )

#     prev_scan = host.last_scan
#     new_scan = Scan(report_html = "this is a test",previous_scan = prev_scan)
#     new_scan.save()
#     host.last_scan = new_scan

#     return HttpResponse(host.last_scan.report_html,200)
