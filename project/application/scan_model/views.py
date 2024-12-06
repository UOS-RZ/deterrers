from django.http import Http404,HttpResponse
from scan_model.models import Scan_report
from django.core.exceptions import ObjectDoesNotExist
import os
from django.shortcuts import get_object_or_404,render
# Create your views here.
def testview(request):
    
    context = {
        "user.get_username ": "test"

    }
    return render(request,'base_generic.html',context)
    
  
