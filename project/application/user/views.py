from django.contrib import messages
from django.contrib.auth.views import LogoutView
from django.shortcuts import render

# Create your views here.
class LogoutMessageView(LogoutView):
    """
    Extends the logout view to add logout messages
    """

    def get_default_redirect_url(self):
        messages.success(self.request, 'You are successfully logged out.')
        return super().get_default_redirect_url()
