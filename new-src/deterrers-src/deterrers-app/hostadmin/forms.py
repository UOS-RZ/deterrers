from django import forms

from .core.host import HostServiceContract, HostFWContract, CustomRuleSubnetContract, CustomRuleProtocolContract


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
        def to_python(self, value) -> list[str]:
            # port specification may have the form <port>, <port>:<port>
            # if two ports are given, they are interpreted as a port range
            if not value:
                return []
            try:
                port_entries = []
                # iterate over all custom port specifications
                for p_str in value.split(','):
                    # check validity of port range
                    port_range = p_str.split(':')
                    assert len(port_range) in (1, 2)
                    for port in port_range:
                        # check that each number is a valid port
                        port = int(port)
                        assert port >= 0
                        assert port < 65536
                    if len(port_range) == 2:
                        # check that, if range is specified, the second port number is bigger than the first one
                        assert int(port_range[1]) > int(port_range[0])
                    port_entries.append(p_str)
            except Exception:
                raise forms.ValidationError("Invalid format for port list.", code="ports_invalid")
            return port_entries

    SUBNET_CHOICES = [(sub.name, sub.display()) for sub in CustomRuleSubnetContract]
    PROTOCOL_CHOICES = [(proto.value, proto.value) for proto in CustomRuleProtocolContract]

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
        help_text='Allow incoming traffic on these ports.\n' \
            'Multiple ports must be seperated by commas. Port ranges can be specified with a collon.',
        required=True,
        widget=forms.TextInput,
    )

    protocol = forms.ChoiceField(
        choices=PROTOCOL_CHOICES,
        label="Protocol:",
        help_text="Allow traffic of this protocol.",
        required=True,
        initial=CustomRuleProtocolContract.ANY.value
    )


