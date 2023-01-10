from django import forms

from .core.host import HostServiceContract, HostFWContract


class ChangeHostDetailForm(forms.Form):
    # create lists of tuples in order to make use of the model validation of django
    SERVICE_CHOICES = [(profile.value, profile.value) for profile in HostServiceContract]
    FW_CHOICES = [(fw.value, fw.value) for fw in HostFWContract]

    service_profile = forms.ChoiceField(
        choices=SERVICE_CHOICES,
        label='Service Profile',
        help_text='Service Profile that has to be chosen for this host.',
        required = False,
        initial=''
    )

    fw = forms.ChoiceField(
        choices=FW_CHOICES,
        label='Host-based Firewall',
        help_text='Host-based Firewall running on this host.',
        required = False,
        initial='',
        show_hidden_initial=True
    )
