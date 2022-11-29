import ipaddress

from django.urls import reverse


class MyHost():
    """
    Custom host class that holds all important information per host in DETERRERS.
    """

    ip_addr = ''
    admin_ids = []
    STATUS_CHOICES = [
        ('U', 'Unscanned'),
        ('R', 'Under Review'),
        ('B', 'Blocked'),
        ('O', 'Online'),
    ]
    status = ''
    name = ""
    SERVICE_CHOICES = [
        ('H', 'HTTP'),
        ('S', 'SSH'),
        ('M', 'Multipurpose'),
        ('', '')
    ]
    service_profile = ''
    FW_CHOICES = [
        ('A', 'UFW'),
        ('B', 'FirewallD'),
        ('', '')
    ]
    fw = ''
    rules = ''
    entity_id = None

    def __init__(self, ip : str, mac : str, admin_ids : list, status : str, name='', service='', fw='', rules='', entity_id=None):
        # Mandatory
        self.ip_addr = ip.replace('_', '.')
        self.mac_addr = mac
        self.admin_ids = admin_ids
        self.status = status
        # Optional
        self.name = name
        self.service_profile = service
        self.fw = fw
        self.rules = rules
        self.entity_id = entity_id


    def __str__(self) -> str:
        return f"Host: {self.ip_addr} ({self.name}) Status: {self.get_status_display()} Service Profile: {self.get_service_profile_display()} FW: {self.get_fw_display()}"

    def get_ip_escaped(self) -> str:
        return str(self.ip_addr).replace('.', '_')

    def get_absolute_url(self):
        """
        Returns the url of this host by using reverse()-function.
        """
        return reverse('host_detail', kwargs={'ip' : self.get_ip_escaped()})

    def get_service_profile_display(self) -> str:
        if self.service_profile:
            for id, desc in self.SERVICE_CHOICES:
                if id == self.service_profile:
                    return desc

        return ''

    def get_fw_display(self) -> str:
        if self.fw:
            for id, desc in self.FW_CHOICES:
                if id == self.fw:
                    return desc

        return ''

    def get_status_display(self) -> str:
        if self.status:
            for id, desc in self.STATUS_CHOICES:
                if id == self.status:
                    return desc

        return ''

    def is_valid(self) -> bool:
        """
        Performs validity check of parameters.

        Returns:
            bool: True for valid and False for invalid.
        """
        try:
            ipaddress.ip_address(self.ip_addr)
        except ValueError:
            return False

        # check for valid mac address format
        if self.mac_addr == '':
            return False
        if len(self.mac_addr.split('-')) != 6:
            return False
        for hex in self.mac_addr.split('-'):
            try:
                int(hex, 16)
            except ValueError:
                return False
        
        if self.status not in [id for id, _ in self.STATUS_CHOICES]:
            return False

        if self.service_profile not in [id for id, _ in self.SERVICE_CHOICES]:
            return False

        if self.fw not in [id for id, _ in self.FW_CHOICES]:
            return False
        
        return True
