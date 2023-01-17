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
        def to_python(self, value) -> list[str]:
            # port specification may have the form <port>, <port>:<port>, <port>/<protocol>, <port>:<port>/<protocol>
            # if no protocl is given, tcp is assumed
            # if two ports are given, they are interpreted as a port range
            if not value:
                return []
            try:
                port_entries = []
                # iterate over all custom port specifications
                for p_str in value.split(','):
                    # split port specification into port range and protocol
                    p_str = p_str.split('/')
                    # check validity of port range
                    port_range = p_str[0].split(':')
                    assert len(port_range) in (1, 2)
                    for port in port_range:
                        # check that each number is a valid port
                        port = int(port)
                        assert port >= 0
                        assert port < 65536
                    if len(port_range) == 2:
                        # check that, if range is specified, the second port number is bigger than the first one
                        assert int(port_range[1]) > int(port_range[0])
                    # (re)attach protocol to port range
                    if len(p_str) == 1:
                        port_spec = ':'.join(port_range) + "/tcp"
                    elif len(p_str) == 2:
                        # check that protocol is valid
                        assert p_str[1] in ("tcp", "udp")
                        port_spec = '/'.join(p_str)
                    else:
                        raise Exception()
                    port_entries.append(port_spec)
            except Exception:
                raise forms.ValidationError("Invalid format for port list.", code="ports_invalid")
            return port_entries

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
        help_text='Allow incoming traffic on these ports. Following forms are allowed seperated by commas:\n' \
            "123 or 123:234 or 123/tcp or 123:234/udp\n"\
            "If no protocol is specified, tcp is assumed.",
        required=True,
        widget=forms.TextInput,
    )


