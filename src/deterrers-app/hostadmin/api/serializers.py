from rest_framework import serializers

from hostadmin.core.rule_generator import HostBasedPolicy
from hostadmin.core.contracts import (HostStatusContract,
                                      HostServiceContract,
                                      HostFWContract)


class MyHostSerializer(serializers.Serializer):
    """
    Serializer class for working with MyHost with the REST framework.
    """
    class HostBasedPolicyField(serializers.Field):
        """
        Custom serializer field for HostBasedPolicy instances.
        """
        def to_representation(self, value: HostBasedPolicy):
            return value.to_string()

        def to_internal_value(self, data: str):
            if not isinstance(data, str):
                msg = 'Incorrect type. Expected a string, but got %s'
                raise serializers.ValidationError(msg % type(data).__name__)

            policy = HostBasedPolicy.from_string(data)
            if not policy:
                raise serializers.ValidationError(
                    "Invalid string representation fo a host-base policy!"
                )
            return policy

    class HostStatusField(serializers.Field):
        """
        Custom serializer field for HostStatusContract instances.
        """
        def to_representation(self, value: HostStatusContract):
            return value.value

        def to_internal_value(self, data: str):
            try:
                return HostStatusContract(data)
            except Exception:
                raise serializers.ValidationError(
                    f"Invalid host status value: {data}"
                )

    class HostServiceField(serializers.Field):
        """
        Custom serializer field for HostServiceContract instances.
        """
        def to_representation(self, value: HostServiceContract):
            return value.value

        def to_internal_value(self, data: str):
            try:
                return HostServiceContract(data)
            except Exception:
                raise serializers.ValidationError(
                    f"Invalid host service profile value: {data}"
                )

    class HostFWField(serializers.Field):
        """
        Custom serializer field for HostFWContract instances.
        """
        def to_representation(self, value: HostFWContract):
            return value.value

        def to_internal_value(self, data: str):
            try:
                return HostFWContract(data)
            except Exception:
                raise serializers.ValidationError(
                    f"Invalid host-based firewall value: {data}"
                )

    # required-keyword specifies which fields are necessary for
    # deserialization
    # read_only-keyword specifies which fields are a present in a serialized
    # object but which may not be given on deserialization
    # ipv4_addr is always required, service_profile and fw may be given for
    # deserialization
    entity_id = serializers.IntegerField(required=False, read_only=True)
    ipv4_addr = serializers.IPAddressField(required=True, protocol='ipv4')
    mac_addr = serializers.CharField(required=False, read_only=True)
    admin_ids = serializers.ListField(required=False,
                                      child=serializers.CharField())
    status = HostStatusField(required=False, read_only=True)
    name = serializers.CharField(required=False, read_only=True)
    dns_rcs = serializers.ListField(
        required=False,
        child=serializers.CharField(read_only=True),
        read_only=True
    )
    service_profile = HostServiceField(required=False)
    fw = HostFWField(required=False)
    host_based_policies = serializers.ListField(required=False,
                                                child=HostBasedPolicyField(),
                                                read_only=True)


class HostActionSerializer(serializers.Serializer):
    ACTION_CHOICES = [
        ('register', 'register'),
        ('block', 'block'),
    ]
    action = serializers.ChoiceField(required=True, choices=ACTION_CHOICES)
    ipv4_addrs = serializers.ListField(
        required=True,
        child=serializers.IPAddressField(protocol='ipv4')
    )
