from django import forms

from .core.host import HostServiceContract, HostFWContract, IntraSubnetContract


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
    


class AddHostRulesForm(forms.Form):

    class PortsField(forms.CharField):
        def to_python(self, value) -> list[int]:
            if not value:
                return []
            try:
                ports = []
                for p_str in value.split(','):
                    port = int(p_str)
                    assert(port >= 0)
                    assert(port < 65536)
                    ports.append(port)
            except Exception:
                raise forms.ValidationError("Invalid format for port list.", code="ports_invalid")
            return ports

    SUBNET_CHOICES = [(sub.name, sub.display()) for sub in IntraSubnetContract]

    subnets = forms.MultipleChoiceField(
        choices=SUBNET_CHOICES,
        label="Allow from:",
        help_text="Allow incoming traffic from these networks.",
        required=True,
        initial='',
        widget=forms.CheckboxSelectMultiple(),
    )

    ports = PortsField(
        label='Ports:',
        help_text='Allow incoming traffic on these ports. Please provide list of numbers seperated by commas.',
        required=True,
        widget=forms.TextInput,
    )


