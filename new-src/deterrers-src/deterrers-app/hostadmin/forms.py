from django import forms
from django.core.exceptions import ValidationError

from .core.host import MyHost


class ChangeHostDetailForm(forms.Form):
    # name = forms.CharField(
    #     max_length=256,
    #     label='Name',
    #     help_text='Descriptive name of this host.',
    #     required = False,
    #     initial=''
    # )

    service_profile = forms.ChoiceField(
        choices=MyHost.SERVICE_CHOICES,
        label='Service Profile',
        help_text='Service Profile that has to be chosen for this host.',
        required = False,
        initial=''
    )

    fw = forms.ChoiceField(
        choices=MyHost.FW_CHOICES,
        label='Host-based Firewall',
        help_text='Host-based Firewall running on this host.',
        required = False,
        initial='',
        show_hidden_initial=True
    )
