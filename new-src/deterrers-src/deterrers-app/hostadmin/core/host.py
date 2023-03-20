import ipaddress

from django.urls import reverse

from rest_framework import serializers

from .rule_generator import HostBasedPolicy
from .contracts import HostFWContract, HostServiceContract, HostStatusContract


class MyHost():
    """
    Custom host class that holds all important information per host in DETERRERS.
    """

    def __init__(
        self,
        entity_id : int,
        ipv4_addr : str,
        mac_addr : str,
        admin_ids : set[str],
        status : HostStatusContract,
        name : str = '',
        dns_rcs : set[str] = set(),
        service_profile : HostServiceContract = HostServiceContract.EMPTY,
        fw : HostFWContract = HostFWContract.EMPTY,
        host_based_policies  : list[HostBasedPolicy] = []):

        # Mandatory
        self.entity_id = int(entity_id)
        try:
            self.ipv4_addr = ipaddress.IPv4Address(ipv4_addr.replace('_', '.'))
        except ipaddress.AddressValueError:
            self.ipv4_addr = None
            return
        self.mac_addr = mac_addr
        self.admin_ids = set(admin_ids)
        self.status = status
        # Optional
        self.name = name
        self.dns_rcs = set(dns_rcs)
        self.service_profile = service_profile
        self.fw = fw
        self.host_based_policies = host_based_policies


    def __str__(self) -> str:
        return f"IPv4: {str(self.ipv4_addr)} ({self.get_dns_rcs_display()}) Status: {self.get_status_display()} Service Profile: {self.get_service_profile_display()} FW: {self.get_fw_display()}"
    
    def __eq__(self, other):
        return ipaddress.IPv4Address(self.ipv4_addr) == ipaddress.IPv4Address(other.ipv4_addr)
    
    def __lt__(self, other):
        return ipaddress.IPv4Address(self.ipv4_addr) < ipaddress.IPv4Address(other.ipv4_addr)

    def get_ip_escaped(self) -> str:
        return str(self.ipv4_addr).replace('.', '_')

    def get_absolute_url(self):
        """
        Returns the url of this host by using reverse()-function.
        """
        return reverse('host_detail', kwargs={'ip' : self.get_ip_escaped()})

    def get_service_profile_display(self) -> str:
        return self.service_profile.value

    def get_fw_display(self) -> str:
        return self.fw.value

    def get_status_display(self) -> str:
        return self.status.value
    
    def get_dns_rcs_display(self) -> str:
        return ", ".join(self.dns_rcs)

    def add_host_based_policy(self, subnets : dict, ports : list[str], proto : str) -> bool:
        new_policy = HostBasedPolicy(subnets, ports, proto)
        for policy in self.host_based_policies:
            if new_policy.is_subset_of(policy):
                return False

        self.host_based_policies.append(new_policy)
        return True

    def is_valid(self) -> bool:
        """
        Performs validity check of parameters.

        Returns:
            bool: True for valid and False for invalid.
        """
        if not isinstance(self.entity_id, int):
            return False
        
        if not isinstance(self.ipv4_addr, ipaddress.IPv4Address):
            return False

        # check for valid mac address format if mac is set
        if self.mac_addr != '':
            if len(self.mac_addr.split('-')) != 6:
                return False
            for hex in self.mac_addr.split('-'):
                try:
                    int(hex, 16)
                except ValueError:
                    return False
        
        if self.status not in HostStatusContract:
            return False

        if self.service_profile not in HostServiceContract:
            return False

        if self.fw not in HostFWContract:
            return False

        for policy in self.host_based_policies:
            if not policy.is_valid():
                return False
        
        return True


class MyHostSerializer(serializers.Serializer):
    class HostBasedPolicyField(serializers.Field):
        def to_representation(self, value : HostBasedPolicy):
            return value.to_string()

        def to_internal_value(self, data : str):
            if not isinstance(data, str):
                msg = 'Incorrect type. Expected a string, but got %s'
                raise serializers.ValidationError(msg % type(data).__name__)
            
            policy = HostBasedPolicy.from_string(data)
            if not policy:
                raise serializers.ValidationError("Invalid string representation fo a host-base policy!")
            return policy
        
    class HostStatusField(serializers.Field):
        def to_representation(self, value : HostStatusContract):
            return value.value

        def to_internal_value(self, data : str):
            try:
                return HostStatusContract(data)
            except:
                raise serializers.ValidationError(f"Invalid host status value: {data}")
        
    class HostServiceField(serializers.Field):
        def to_representation(self, value : HostServiceContract):
            return value.value

        def to_internal_value(self, data : str):
            try:
                return HostServiceContract(data)
            except:
                raise serializers.ValidationError(f"Invalid host service profile value: {data}")
        
    class HostFWField(serializers.Field):
        def to_representation(self, value : HostFWContract):
            return value.value

        def to_internal_value(self, data : str):
            try:
                return HostFWContract(data)
            except:
                raise serializers.ValidationError(f"Invalid host-based firewall value: {data}")
            
    
    # Mandatory
    entity_id = serializers.IntegerField()
    ipv4_addr = serializers.IPAddressField(protocol='ipv4')
    mac_addr = serializers.CharField()
    admin_ids = serializers.ListField(child=serializers.CharField())
    status = HostStatusField()
    # Optional
    name = serializers.CharField(required=False)
    dns_rcs = serializers.ListField(required=False, child=serializers.CharField())
    service_profile = HostServiceField(required=False)
    fw = HostFWField(required=False)
    host_based_policies = serializers.ListField(required=False, child=HostBasedPolicyField())

    def create(self, validated_data):
        return MyHost(**validated_data)

    def update(self, instance, validated_data):
        instance.entity_id = validated_data.get('entity_id', instance.entity_id)
        instance.ipv4_addr = validated_data.get('ipv4_addr', instance.conipv4_addrtent)
        instance.mac_addr = validated_data.get('mac_addr', instance.mac_addr)
        instance.admin_ids = validated_data.get('admin_ids', instance.admin_ids)
        instance.status = validated_data.get('status', instance.status)
        instance.name = validated_data.get('name', instance.name)
        instance.dns_rcs = validated_data.get('dns_rcs', instance.dns_rcs)
        instance.service_profile = validated_data.get('service_profile', instance.service_profile)
        instance.fw = validated_data.get('fw', instance.fw)
        instance.host_based_policies = validated_data.get('host_based_policies', instance.host_based_policies)
        return instance
