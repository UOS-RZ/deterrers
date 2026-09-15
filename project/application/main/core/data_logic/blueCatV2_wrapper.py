from bluecat_libraries.address_manager.apiv2 import Client

import logging
import json
import ipaddress
import socket

from main.core.data_logic.data_abstract import DataAbstract
from main.core.host import MyHost
from main.core.contracts import (HostStatus,
                                 HostServiceProfile,
                                 HostFW)
from main.core.rule_generator import HostBasedPolicy

logger = logging.getLogger(__name__)


class ProteusV2IPAMWrapper(DataAbstract):
    """Wrapper for BlueCat IPAM REST API v2."""

    TAG_GROUP_NAME = "Deterrers Host Admins"

    def __init__(self, username: str, password: str, url: str) -> None:
        """Initialize the BlueCat IPAM v2 wrapper.

        Args:
            username (str): Username for BlueCat IPAM authentication.
            password (str): Password for BlueCat IPAM authentication.
            url (str): Base URL of the BlueCat IPAM API.
        """
        super().__init__(username, password, url)
        self.client = None
        self.__admin_names_by_tag_id = None
        self.__department_tag_ids = {}

    def __enter__(self):
        """Open a session to the BlueCat IPAM API v2.

        Returns:
            ProteusV2IPAMWrapper: Self reference for use in with-statements.
        """
        try:
            self.client = Client(self.url)
            self.client.login(self.username, self._password)
            logger.debug("Successfully connected to BlueCat IPAM API v2.")
            self.enter_ok = True
        except Exception as e:
            logger.exception(f"Failed to connect to BlueCat IPAM API v2: {e}")
            self.enter_ok = False
        return self
    
    def __exit__(self, exc_type, exc_value, traceback):
        """Close the session to the BlueCat IPAM API v2."""
        if self.client and self.enter_ok:
            try:
                self.client.logout()
                logger.debug("Closed connection to BlueCat IPAM API v2.")
            except Exception as e:
                logger.exception(f"Error closing connection: {e}")

    def __get_tag_group_id(self) -> int | None:
        """
        Get the tag group ID for 'Deterrers Host Admins'.
        Returns:
            int | None: Tag group ID or None if not found.
        """
        try:
            tag_group_resp = self.client.http_get(
                "/tagGroups",
                params={"filter": f"name:'{self.TAG_GROUP_NAME}'"}
            )
            tag_group = next(
                (
                    group for group in tag_group_resp.get("data", [])
                    if group.get("name") == self.TAG_GROUP_NAME
                ),
                None
            )
            if tag_group:
                return int(tag_group["id"])
        except Exception:
            logger.exception("Couldn't query tag group from IPAM!")

        return None

    def get_host_info_from_ip(self, ipv4: str) -> MyHost | None:
        """
        Queries the BlueCat IPAM API v2 for an entity with the given IP and
        returns an instance of MyHost.

        Args:
            ipv4 (str): IPv4 address of the host entity in the BlueCat IPAM
            system.

        Returns:
            MyHost: Returns an instance of MyHost populated with the fields
            from the IPAM system and None on error.
        """

        try:
            ip_obj = ipaddress.IPv4Address(ipv4)
            response_data = self.client.http_get("/addresses", params={"filter": f"address:'{ip_obj}'", "limit": 1})["data"]
            
            if not response_data or len(response_data) == 0:
                logger.warning(f"No host found for IP {ipv4}")
                return None
            
            data = response_data[0]
            
            try:
                host_id = data["id"]
            except KeyError:
                host_id = None
            try:
                name = data["name"]
            except KeyError:
                name = ''
            try:
                ip = data["address"]
            except KeyError:
                ip = ''
            
            try:
                mac = data["macAddress"]["address"]
            except (KeyError, TypeError):
                mac = ''
            
            udf = data.get("userDefinedFields", {})
            status = udf.get("deterrers_status")
            service_profile = udf.get("deterrers_service_profile")
            fw = udf.get("deterrers_fw")
            
            rules_str = udf.get("deterrers_rules") or "[]"
            rules = []
            try:
                rules_list = json.loads(rules_str)
                if isinstance(rules_list, list):
                    for rule_item in rules_list:
                        if rule_item:
                            policy = HostBasedPolicy.from_string(rule_item)
                            if policy:
                                rules.append(policy)
            except (json.JSONDecodeError, ValueError, TypeError):
                rules = []
            comment = udf.get("comment")

            dns_rcs = self.__get_linked_dns_records(host_id, ip)
            direct_admin_tags = self.__get_direct_admin_tags(host_id)
            
            my_host = MyHost(
                entity_id=int(host_id),
                ipv4_addr=ip,
                mac_addr=mac,
                admin_ids=set(),
                direct_admin_tags=direct_admin_tags,
                status=HostStatus(status) if status else HostStatus.UNREGISTERED,
                name=name,
                dns_rcs=set(dns_rcs),
                service_profile=HostServiceProfile(service_profile) if service_profile else HostServiceProfile.EMPTY,
                fw=HostFW(fw) if fw else HostFW.EMPTY,
                host_based_policies=rules,
                comment=comment if comment else "",
            )
            self.__refresh_effective_admins(my_host)

            if my_host.is_valid():
                return my_host
            else:
                logger.warning("Host '%s' is not valid!", ipv4)
                return None
            
        except Exception as e:
            logger.exception(f"Error retrieving host info for IP {ipv4}: {e}")
            return None

    def __get_admin_names_by_tag_id(self) -> dict[int, tuple[str, ...]]:
        """Load the tag ID to effective names lookup once per wrapper.

        An admin tag ID maps to that admin's name. A department tag ID maps
        to the department name followed by every admin in that department.
        For example::

            {
                department_id: ("department", "admin-a", "admin-b"),
                admin_a_id: ("admin-a",),
                admin_b_id: ("admin-b",),
            }

        Separate IDs preserve admins belonging to multiple departments.
        Department IDs are also kept so empty departments can be distinguished
        from leaf admin tags; neither needs a separate reverse lookup.
        """
        if self.__admin_names_by_tag_id is not None:
            return self.__admin_names_by_tag_id

        try:
            tag_group_id = self.__get_tag_group_id()
            if tag_group_id is None:
                logger.warning(
                    "Tag group ID for '%s' not found.",
                    self.TAG_GROUP_NAME
                )
                return {}

            department_resp = self.client.http_get(
                f"/tagGroups/{tag_group_id}/tags",
                params={"fields": "embed(tags)", "limit": 100000}
            )
            departments = department_resp.get("data", [])
            names_by_tag_id = {}
            department_tag_ids = {}

            for department in departments:
                department_id = department.get("id")
                department_name = department.get("name")
                if not department_id or not department_name:
                    continue
                embedded = department.get("_embedded", {}) or {}
                admins = embedded.get("tags", [])

                department_id = int(department_id)
                department_tag_ids[department_name] = department_id
                expanded_names = [department_name]

                for admin in admins:
                    admin_id = admin.get("id")
                    admin_name = admin.get("name")
                    if not admin_id or not admin_name:
                        continue
                    admin_id = int(admin_id)
                    names_by_tag_id[admin_id] = (admin_name,)
                    expanded_names.append(admin_name)

                names_by_tag_id[department_id] = tuple(expanded_names)

            self.__department_tag_ids = department_tag_ids
            self.__admin_names_by_tag_id = names_by_tag_id
            return names_by_tag_id
        except Exception:
            logger.exception(
                "Could not build the BlueCat V2 host-admin hierarchy."
            )
            return {}

    def __get_direct_admin_tags(self,host_id: int) -> dict[int, str]:
        """Read the admin and department tags directly attached to a host.

        Tags outside ``Deterrers Host Admins`` are ignored.

        Args:
            host_id (int): Entity ID of the host in the BlueCat IPAM system.

        Returns:
            dict[int, str]: Direct tag IDs mapped to their names.
        """
        try:
            tag_index = self.__get_admin_names_by_tag_id()
            if not tag_index:
                return {}
            tags_resp = self.client.http_get(
                f"/addresses/{host_id}/tags",
                params={"limit": 100000}
            )
            direct_admin_tags = {}
            for tag in tags_resp.get("data", []):
                try:
                    tag_id = int(tag["id"])
                except (KeyError, TypeError, ValueError):
                    continue
                tag_names = tag_index.get(tag_id, ())
                if not tag_names:
                    continue
                direct_admin_tags[tag_id] = tag_names[0]

            return direct_admin_tags
        except Exception:
            logger.exception("Couldn't query direct host-admin tags!")
            return {}

    def __refresh_effective_admins(self, host: MyHost) -> None:
        """Derive effective admins from the host's direct tag attachments."""
        tag_index = self.__get_admin_names_by_tag_id()
        effective_admins = set()

        for tag_id in (host.direct_admin_tags or {}):
            effective_admins.update(tag_index.get(tag_id, ()))

        host.admin_ids = effective_admins
    
    def __get_linked_dns_records(self, address_id: int, ip: str) -> set[str]:
        """Query DNS records linked to an IPv4 address entity.

        Falls back to a socket-based reverse DNS lookup if the API
        query fails.

        Args:
            address_id (int): Entity ID of the IPv4 address in BlueCat.
            ip (str): IPv4 address string used for fallback DNS lookup.

        Returns:
            set[str]: Set of DNS names associated with the address.
        """
        dns_names = set()
        try:
            records_resp = self.client.http_get(f"/addresses/{address_id}/resourceRecords")
            for record in records_resp.get("data", []):
                rec_type = record.get("type")
                if rec_type in {"HostRecord", "ExternalHostRecord"}:
                    name = record.get("absoluteName") or record.get("name")
                    if name:
                        dns_names.add(name)
        except Exception:
            # Fallback to socket-based DNS lookup
            try:
                host_info = socket.gethostbyaddr(ip)
                dns_names.add(host_info[0])
                for alias in host_info[1]:
                    dns_names.add(alias)
            except (socket.herror, OSError):
                pass

        return dns_names
    
    def get_hosts_of_admin(self, admin_name: str) -> list[MyHost]:
        """Query all hosts tagged with an admin or their parent department tag.

        Args:
            admin_name (str): Identifier string for the admin tag.

        Returns:
            list[MyHost]: List of unique MyHost instances associated with
            the admin.
        """
        hosts = []
        try:
            tag_index = self.__get_admin_names_by_tag_id()
            candidate_ips = set()
            for tid, names in tag_index.items():
                if admin_name not in names:
                    continue
                tagged_resp = self.client.http_get(
                    f"/tags/{tid}/taggedResources",
                    params={"filter": "type:'IPv4Address'", "limit": "10000"}
                )
                tagged_resources = tagged_resp.get("data", [])

                for addr in tagged_resources:
                    ip = addr.get("address")
                    if ip:
                        candidate_ips.add(ip)

            for ip in candidate_ips:
                host = self.get_host_info_from_ip(ip)
                if host and admin_name in host.admin_ids:
                    hosts.append(host)

        except Exception:
            logger.exception("Caught an unknown exception!")

        return hosts

    def get_IP6Addresses(self, host: MyHost) -> set[str]:
        """
        Query public IPv6 addresses linked to a host's IPv4 address via
        shared HostRecords in the BlueCat IPAM API v2.

        Args:
            host (MyHost): Host instance for which IPv6 addresses are queried.

        Returns:
            set[str]: Set of public IPv6 address strings in exploded form.
        """
        try:
            ipv4_id = host.entity_id
            records_resp = self.client.http_get(
                f"/addresses/{ipv4_id}/resourceRecords"
            )
            all_addresses = set()
            for record in records_resp.get("data", []):
                if record.get("type") != "HostRecord":
                    continue
                record_id = record.get("id")
                if not record_id:
                    continue
                addr_resp = self.client.http_get(
                    f"/resourceRecords/{record_id}/addresses"
                )
                for addr in addr_resp.get("data", []):
                    address = addr.get("address")
                    if address:
                        all_addresses.add(address)

            ipv6_addrs = set()
            for ip in all_addresses:
                try:
                    ipv6 = ipaddress.IPv6Address(ip)
                    if not ipv6.is_private:
                        ipv6_addrs.add(ipv6.exploded)
                except ipaddress.AddressValueError:
                    continue

            return ipv6_addrs

        except Exception:
            logger.exception(
                "Couldn't get IPv6 addresses for host %s!", host.ipv4_addr
            )
            return set()

    def get_department_names(self) -> list:
        """
        Get all department tag names.

        Returns:
            list: Returns list of department tag names.
        """
        self.__get_admin_names_by_tag_id()
        return list(self.__department_tag_ids)

    def get_department_to_admin(self, admin_name: str) -> str | None:
        """Get one department for compatibility with the legacy interface.

        Args:
            admin_name (str): Name of the admin tag.

        Returns:
            str | None: Alphabetically first department or None if not found.

        New V2 code should use ``get_departments_to_admin`` because an admin
        can belong to more than one department.
        """
        departments = self.get_departments_to_admin(admin_name)
        return min(departments, default=None)

    def get_departments_to_admin(self, admin_name: str) -> set[str]:
        """Get all department names for an admin tag name."""
        tag_index = self.__get_admin_names_by_tag_id()
        return {
            department
            for department, tag_id in self.__department_tag_ids.items()
            if admin_name in tag_index.get(tag_id, ())[1:]
        }

    def get_all_admin_names(self) -> set[str]:
        """
        Query all admin tag names from all departments.

        Returns:
            set[str]: Returns a set of unique admin tag names.
        """
        tag_index = self.__get_admin_names_by_tag_id()
        return {
            admin for tag_id in self.__department_tag_ids.values()
            for admin in tag_index.get(tag_id, ())[1:]
        }

    def create_admin(self, admin_name: str, department_name: str) -> bool:
        """
        Create an admin tag under a department tag.

        Args:
            admin_name (str): Name of the admin tag to create.
            department_name (str): Name of the department tag that already exists.

        Returns:
            bool: True on success, False on error or if already exists.
        """
        try:
            if self.is_admin(admin_name):
                return False

            department_tag_id = self.__department_tag_ids.get(department_name)

            if not department_tag_id:
                return False

            response = self.client.http_post(f"/tags/{department_tag_id}/tags", json={"name": admin_name})
            if response and isinstance(response, dict) and response.get("id"):
                # Reset cached hierarchy so follow-up reads include new admin.
                self.__admin_names_by_tag_id = None
                self.__department_tag_ids = {}
                return True
            else:
                logger.error("Failed to create tag for admin %s!", admin_name)
                return False

        except Exception:
            logger.exception("Couldn't create a tag for admin %s!", admin_name)
            return False

    def is_admin(self, admin_name: str) -> bool:
        """
        Check whether an admin tag with the given name exists.

        Args:
            admin_name (str): Name of the admin tag to check.

        Returns:
            bool: True if the admin exists. False if absent or the hierarchy
                could not be loaded.
        """
        return admin_name in self.get_all_admin_names()

    def add_admin_to_host(self, admin_name: str, host: MyHost) -> int:
        """
        Link an admin/department tag to a host address.

        Args:
            admin_name (str): Tag name corresponding to admin or department.
            host (MyHost): Host instance for which admin is added.

        Returns:
            int: 200 if linked or already directly attached, 404 if the name
                is unknown, 500 if linking fails.
        """
        try:
            host_id = host.entity_id

            if admin_name in host.direct_admin_names:
                return 200

            tag_index = self.__get_admin_names_by_tag_id()
            # Same-named leaf tags grant the same access; one link suffices.
            tag_id = min(
                (tid for tid, names in tag_index.items()
                 if names[0] == admin_name),
                default=None,
            )
            if tag_id is None:
                return 404

            response = self.client.http_post(f"/addresses/{host_id}/tags", json={"id": tag_id})
            if response and isinstance(response, dict) and response.get("id"):
                if host.direct_admin_tags is None:
                    host.direct_admin_tags = {}
                host.direct_admin_tags[tag_id] = admin_name
                self.__refresh_effective_admins(host)
                return 200
            else:
                logger.error(f"Failed to add tag '{admin_name}' to host {host.ipv4_addr}")
                return 500
            
        except Exception:
            logger.exception(f"Couldn't add tag '{admin_name}' to host {host.ipv4_addr}!")
            return 500

    def remove_admin_from_host(self, admin_name: str, host: MyHost) -> int:
        """
        Unlink an admin/department tag from a host address.

        Args:
            admin_name (str): Tag name corresponding to admin or department.
            host (MyHost): Host instance.

        Returns:
            int: 200 if removed or not directly attached, 500 on error.
        """
        try:
            host_id = host.entity_id
            direct_admin_tags = host.direct_admin_tags or {}
            tag_id = next(
                (
                    tag_id for tag_id, tag_name in direct_admin_tags.items()
                    if tag_name == admin_name
                ),
                None
            )
            if tag_id is None:
                return 200

            response = self.client.http_delete(f"/addresses/{host_id}/tags/{tag_id}")
            if response is not None:
                del direct_admin_tags[tag_id]
                self.__refresh_effective_admins(host)
                return 200
            else:
                logger.error(f"Failed to remove tag '{admin_name}' from host {host.ipv4_addr}")
                return 500

        except Exception:
            logger.exception(f"Couldn't remove tag '{admin_name}' from host {host.ipv4_addr}!")
            return 500

    def update_host_info(self, host: MyHost) -> bool:
        """
        Updates host information in the BlueCat IPAM system (v2).

        Args:
            host (MyHost): Host instance that holds all the latest information.

        Returns:
            bool: Returns True on success and False on error.
        """
        if hasattr(host, "is_valid") and not host.is_valid():
            logger.error("Host not valid: %s", str(host))
            return False

        try:
            rules_list = []
            for policy in host.host_based_policies or []:
                if hasattr(policy, "to_string"):
                    rules_list.append(policy.to_string())
                else:
                    rules_list.append(policy)

            current_resp = self.client.http_get(f"/addresses/{host.entity_id}")
            current_data = current_resp
            current_udf = current_data.get("userDefinedFields") or {}

            user_defined_fields = {
                **current_udf,
                "deterrers_service_profile": host.get_service_profile_display() if hasattr(host, "get_service_profile_display") else str(getattr(host, "service_profile", "")),
                "deterrers_fw": host.get_fw_display() if hasattr(host, "get_fw_display") else str(getattr(host, "fw", "")),
                "deterrers_status": host.get_status_display() if hasattr(host, "get_status_display") else str(getattr(host, "status", "")),
                "deterrers_rules": json.dumps(rules_list),
                "comment": getattr(host, "comment", "") or "",
            }
            if "admin_email" not in user_defined_fields and "admin_email" in current_udf:
                user_defined_fields["admin_email"] = current_udf["admin_email"]

            payload = {
                "id": host.entity_id,
                "name": getattr(host, "name", None) or current_data.get("name"),
                "type": current_data.get("type") or "IPv4Address",
                "state": current_data.get("state"),
                "macAddress": current_data.get("macAddress"),
                "userDefinedFields": user_defined_fields,
            }

            response = self.client.http_put(f"/addresses/{host.entity_id}", json=payload)
            if response and isinstance(response, dict) and response.get("id"):
                return True
            else:
                logger.error(f"Failed to update host info for {host.ipv4_addr}")
                return False

        except Exception:
            logger.exception("Caught an unknown exception!")
            return False

    def user_exists(self, username: str) -> bool | None:
        """
        Check whether a user of given name exists.

        Args:
            username (str): Name of the queried user.

        Returns:
            bool|None: Returns True if user exists, False if not and None if something went wrong.
        """
        try:
            resp = self.client.http_get("/users", params={"filter": f"name:'{username}'"})
            users = resp.get("data", [])
            return len(users) > 0
        except Exception:
            logger.exception("Couldn't query IPAM whether user exists!")
            return None
