from django import forms

from .core.contracts import HostBasedRuleSubnetContract, HostBasedRuleProtocolContract, HostServiceContract, HostFWContract

class HostadminForm(forms.Form):
    def __init__(self, *args, **kwargs):
        choices = kwargs.pop('choices')
        super(HostadminForm, self).__init__(*args, **kwargs)
        self.fields["department"] = forms.ChoiceField(choices=[(c, c) for c in choices], required=True, label='Departments:')


class AddHostForm(forms.Form):
    def __init__(self, *args, **kwargs):
        choices = kwargs.pop('choices')
        super(AddHostForm, self).__init__(*args, **kwargs)
        self.fields["admin_tag"] = forms.ChoiceField(
            choices=[(c, c) for c in choices],
            required=True,
            label='Admin(s):',
            help_text="Are you the only admin or should other admins from your department have the same acces as you."
        )

    ip_addr = forms.GenericIPAddressField(
        protocol='IPv4',
        unpack_ipv4=False,
        label='IP Address',
        help_text='IPv4 Address of the host.',
        required=True,
    )


class ChangeHostDetailForm(forms.Form):
    # create lists of tuples in order to make use of the model validation of django
    SERVICE_CHOICES = [(profile.value, profile.value) for profile in HostServiceContract]
    FW_CHOICES = [(fw.value, fw.value) for fw in HostFWContract]

    service_profile = forms.ChoiceField(
        choices=SERVICE_CHOICES,
        label='Service Profile',
        help_text='Internet Service Profile that has to be chosen for this host.',
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

    SUBNET_CHOICES = [(sub.name, sub.display()) for sub in HostBasedRuleSubnetContract]
    PROTOCOL_CHOICES = [(proto.value, proto.value) for proto in HostBasedRuleProtocolContract]

    subnet = forms.ChoiceField(
        choices=SUBNET_CHOICES,
        label="Allow from:",
        help_text="Allow incoming traffic from this network.",
        required=True,
        widget=forms.Select(),
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
    )


