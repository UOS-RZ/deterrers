from django.http import Http404,HttpResponse
from scan_model.models import Scan_report,Vulnerability
from django.core.exceptions import ObjectDoesNotExist
import os
from django.shortcuts import get_object_or_404,render
# Create your views here.
def testview(request):

    return HttpResponse("",200)
  
