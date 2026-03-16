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
        super().__init__(username, password, url)
        self.client = None
        self.__tag_group_id = None
        self.__department_tags = None

    def __enter__(self):
        try:
            self.client = Client(self.url)
            self.client.login(self.username, self._password)
            logger.info("Successfully connected to BlueCat IPAM API v2.")
            self.enter_ok = True
        except Exception as e:
            logger.exception(f"Failed to connect to BlueCat IPAM API v2: {e}")
            self.enter_ok = False
        return self
    
    def __exit__(self, exc_type, exc_value, traceback):
        if self.client:
            try:
                self.client.logout()
                logger.info("Closed connection to BlueCat IPAM API v2.")
            except Exception as e:
                logger.exception(f"Error closing connection: {e}")

    def __get_tag_group_id(self) -> int | None:
        """
        Get the tag group ID for 'Deterrers Host Admins'.
        Result is cached in self.__tag_group_id.

        Returns:
            int | None: Tag group ID or None if not found.
        """
        if self.__tag_group_id is not None:
            return self.__tag_group_id

        try:
            tag_group_resp = self.client.http_get("/tagGroups", params={"filter": f"name:'{self.TAG_GROUP_NAME}'"})
            tag_group = tag_group_resp.get("data", [])
            if tag_group:
                self.__tag_group_id = tag_group[0].get("id")
                return self.__tag_group_id
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
            except KeyError:
                mac = None
            
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
            tagged_admins = self.__get_admins_of_host(host_id)
            
            return MyHost(
                entity_id=int(host_id),
                ipv4_addr=ip,
                mac_addr=mac,
                admin_ids=set(tagged_admins),
                status=HostStatus(status) if status else HostStatus.EMPTY,
                name=name,
                dns_rcs=set(dns_rcs),
                service_profile=HostServiceProfile(service_profile) if service_profile else HostServiceProfile.EMPTY,
                fw=HostFW(fw) if fw else HostFW.EMPTY,
                host_based_policies=rules,
                comment=comment if comment else "",
            )
            
        except Exception as e:
            logger.exception(f"Error retrieving host info for IP {ipv4}: {e}")
            return None

    def __get_admins_of_host(self, host_id: int) -> list:
        """
        Queries the BlueCat IPAM API v2 for all tagged admins of a host.

        Args:
            host_id (int): Entity ID of the host in the BlueCat IPAM system.

        Returns:
            list: Returns a list of admin rz-ids.
        """
        tagged_admins = []
        try:
            tags_resp = self.client.http_get(f"/addresses/{host_id}/tags")
            tags = tags_resp.get("data", [])
            
            for tag in tags:
                tag_id = tag.get("name")
                if tag_id:
                    tagged_admins.append(tag_id)
                        
        except Exception:
            logger.exception("Caught an unknown exception!")

        return tagged_admins
    
    def __get_linked_dns_records(self, address_id: int, ip: str) -> set[str]:
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
        hosts = []
        try:
            tag_resp = self.client.http_get("/tags", params={"filter": f"name:'{admin_name}'"})
            tags = tag_resp.get("data", [])
            if not tags:
                return []
            
            tag_id = tags[0].get("id")
            
            department_name = self.get_department_to_admin(admin_name)
            parent_id = None
            if department_name:
                dep_resp = self.client.http_get("/tags", params={"filter": f"name:'{department_name}'"})
                parent_id = (dep_resp.get("data", [{}])[0] or {}).get("id")
            
            tag_ids_to_query = [tag_id]
            if parent_id:
                tag_ids_to_query.append(parent_id)
    
            for tid in tag_ids_to_query:
                try:
                    tagged_resp = self.client.http_get(
                        f"/tags/{tid}/taggedResources",
                        params={"filter": "type:'IPv4Address'", "limit": "10000"}
                    )
                    tagged_resources = tagged_resp.get("data", [])
                except Exception:
                    logger.warning(f"API filtering for IPv4Address type failed for tag ID {tid}, falling back to unfiltered query and manual filtering.")
                    tagged_resp = self.client.http_get(
                        f"/tags/{tid}/taggedResources",
                        params={"limit": "10000"}
                    )
                    tagged_resources = tagged_resp.get("data", [])
                    tagged_resources = [res for res in tagged_resources if res.get("type") == "IPv4Address"]

                for addr in tagged_resources:
                    ip = addr.get("address")
                    if ip:
                        host = self.get_host_info_from_ip(ip)
                        if host:
                            hosts.append(host)
                        
        except Exception:
            logger.exception("Caught an unknown exception!")
        
        seen_ips = set()
        unique_hosts = []
        for host in hosts:
            ip_str = str(host.ipv4_addr)
            if ip_str not in seen_ips:
                seen_ips.add(ip_str)
                unique_hosts.append(host)
        
        return unique_hosts

    def get_IP6Addresses(self, host: MyHost) -> set[str]:
        """
        Resolve IPv6 addresses for a host using DNS (AAAA records).

        Args:
            host (MyHost): Host instance.

        Returns:
            set[str]: Set of IPv6 address strings.
        """
        try:
            name = getattr(host, "name", None)
            if not name:
                return set()
            results = socket.getaddrinfo(name, None, socket.AF_INET6)
            return {r[4][0] for r in results if r and r[4]}
        except Exception:
            return set()

    def get_department_names(self) -> list:
        """
        Get all department tag names.

        Returns:
            list: Returns list of department tag names.
        """
        names = []
        try:
            tag_group_id = self.__get_tag_group_id()
            if not tag_group_id:
                return names
            
            dept_resp = self.client.http_get(f"/tagGroups/{tag_group_id}/tags")
            departments = dept_resp.get("data", [])
            
            for dept in departments:
                dept_name = dept.get("name")
                if dept_name:
                    names.append(dept_name)
            
            return names
        except Exception:
            logger.exception("Couldn't query department tag names from IPAM!")
            return names

    def get_department_to_admin(self, admin_name: str) -> str | None:
        try:
            tag_resp = self.client.http_get("/tags", params={"filter": f"name:'{admin_name}'"})
            tags = tag_resp.get("data", [])
            if not tags:
                return None
            tag_id = tags[0].get("id")
            if not tag_id:
                return None
            tag_detail = self.client.http_get(f"/tags/{tag_id}")
            tag_data = tag_detail.get("data", tag_detail)
            up_link = (tag_data.get("_links", {}) or {}).get("up", {}).get("href")
            if not up_link:
                return None
            parent_detail = self.client.http_get(up_link.replace("/api/v2", ""))
            parent_data = parent_detail.get("data", parent_detail)
            return parent_data.get("name")
        except Exception:
            logger.exception("Couldn't query parent tag from IPAM!")
        return None

    def get_all_admin_names(self) -> set[str]:
        """
        Query all admin tag names from all departments.

        Returns:
            set[str]: Returns a set of unique admin tag names.
        """
        admin_tag_names = []
        try:
            tag_group_id = self.__get_tag_group_id()
            if not tag_group_id:
                return set()
            
            dept_resp = self.client.http_get(f"/tagGroups/{tag_group_id}/tags")
            departments = dept_resp.get("data", [])
            
            for dept in departments:
                dept_id = dept.get("id")
                admin_resp = self.client.http_get(f"/tags/{dept_id}/tags")
                admin_tags = admin_resp.get("data", [])
                for admin in admin_tags:
                    admin_name = admin.get("name")
                    if admin_name:
                        admin_tag_names.append(admin_name)
            
            return set(admin_tag_names)
        except Exception:
            logger.exception("Couldn't query admin tag names from IPAM!")
        return set()

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

            tag_group_id = self.__get_tag_group_id()
            if not tag_group_id:
                return False

            dept_resp = self.client.http_get(f"/tagGroups/{tag_group_id}/tags")
            departments = dept_resp.get("data", [])

            department_tag_id = None
            for dept in departments:
                if dept.get("name") == department_name:
                    department_tag_id = dept.get("id")
                    break

            if not department_tag_id:
                return False

            self.client.http_post(f"/tags/{department_tag_id}/tags", json={"name": admin_name})
            return True

        except Exception:
            logger.exception("Couldn't create a tag for admin %s!", admin_name)
            return False

    def is_admin(self, admin_name: str) -> bool | None:
        """
        Check whether an admin tag with the given name exists.

        Args:
            admin_name (str): Name of the admin tag to check.

        Returns:
            bool | None: Returns True if admin exists, False if not, and None on error.
        """
        try:
            all_admins = self.get_all_admin_names()
            return admin_name in all_admins
        except Exception:
            logger.exception(f"Couldn't check if admin '{admin_name}' exists!")
            return None

    def add_admin_to_host(self, admin_name: str, host: MyHost) -> int:
        """
        Link an admin/department tag to a host address.

        Args:
            admin_name (str): Tag name corresponding to admin or department.
            host (MyHost): Host instance for which admin is added.

        Returns:
            int: Returns HTTP status code (200 on success, 500 on error).
        """
        try:
            host_id = host.entity_id
            
            tag_resp = self.client.http_get("/tags", params={"filter": f"name:'{admin_name}'"})
            tag_list = tag_resp.get("data", [])
            if not tag_list:
                return 404
            
            tag_id = tag_list[0].get("id")
            
            tags_resp = self.client.http_get(f"/addresses/{host_id}/tags")
            host_tags = tags_resp.get("data", [])

            host_tag_ids = {t.get("id") for t in host_tags}
            if tag_id in host_tag_ids:
                return 200
            
            response = self.client.http_post(f"/addresses/{host_id}/tags", json={"id": tag_id})
            if response and isinstance(response, dict) and response.get("data"):
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
            int: Returns HTTP status code (200 on success, 404 if tag not found, 500 on error).
        """
        try:
            host_id = host.entity_id

            # Get tag ID from admin name
            tag_resp = self.client.http_get("/tags", params={"filter": f"name:'{admin_name}'"})
            tag_list = tag_resp.get("data", [])
            if not tag_list:
                return 404

            tag_id = tag_list[0].get("id")

            tags_resp = self.client.http_get(f"/addresses/{host_id}/tags")
            host_tags = tags_resp.get("data", [])
            host_tag_ids = {t.get("id") for t in host_tags}

            if tag_id not in host_tag_ids:
                return 200

            response = self.client.http_delete(f"/addresses/{host_id}/tags/{tag_id}")
            if response is not None:
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
            current_data = current_resp.get("data", current_resp)
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
            if response and isinstance(response, dict) and response.get("data"):
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