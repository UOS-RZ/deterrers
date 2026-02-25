from bluecat_libraries.address_manager.apiv2 import Client, MediaType

import logging
import json
import ipaddress
import socket
import requests



#   from distro import name
#from tomlkit import comment

from main.core.data_logic.data_abstract import DataAbstract
from main.core.host import MyHost
from main.core.contracts import (HostStatus,
                                 HostServiceProfile,
                                 HostFW)
from main.core.rule_generator import HostBasedPolicy

logger = logging.getLogger(__name__)


class ProteusV2IPAMWrapper(DataAbstract):
    """ Wrapper for BlueCat Proteus IPAM API v2."""

    TAG_GROUP_NAME = "Deterrers Host Admins"

    def __init__(self, username: str, password: str, url: str) -> None:
        super().__init__(username, password, url)
        self.client = None
        self.__tag_group_id = None
        self.__department_tags = None

    def __enter__(self):
        try:
            # Client expects just the URL, authentication is done via login() or context manager
            self.client = Client(self.url)
            # Try to login
            self.client.login(self.username, self._password)
            logging.info("Successfully connected to BlueCat Proteus IPAM API v2.")
            self.enter_ok = True
        except Exception as e:
            logging.error(f"Failed to connect to BlueCat Proteus IPAM API v2: {e}")
            self.enter_ok = False
        return self
    
    def __exit__(self, exc_type, exc_value, traceback):
        if self.client:
            try:
                self.client.logout()
                logging.info("Closed connection to BlueCat Proteus IPAM API v2.")
            except Exception as e:
                logging.error(f"Error closing connection: {e}")

    def get_host_info_from_ip(self, ipv4: str) -> MyHost | None:
        """
        Queries the Proteus IPAM API for an entity with the given IP and
        returns an instance of MyHost.

        Args:
            ipv4 (str): IPv4 address of the host entity in the Proteus IPAM
            system.

        Returns:
            MyHost: Returns an instance of MyHost populated with the fields
            from the IPAM system and None on error.
        """

        try:
            ip_obj = ipaddress.IPv4Address(ipv4)
            # Use the correct API v2 method - http_get returns dict directly
            response_data = self.client.http_get("/addresses", params={"filter": f"address:'{ip_obj}'", "limit": 1})["data"]
            
            # Check if we got results
            if not response_data or len(response_data) == 0:
                logging.warning(f"No host found for IP {ipv4}")
                return None
            
            # Extract first item from the list
            data = response_data[0]
            #print("Raw API response:", data)  # Debugging line
            
            # Extract fields
            host_id = data["id"]
            name = data["name"]
            ip = data["address"]
            
            try:
                mac = data["macAddress"]["address"]
            except (KeyError, TypeError):
                mac = None
            
            udf = data.get("userDefinedFields", {})
            #### status
            try:
                status = udf.get("deterrers_status")
            except:
                status = None
            #### service profile
            try: 
                service_profile = udf.get("deterrers_service_profile")
            except:
                service_profile = None
            #### firewall
            try:
                fw = udf.get("deterrers_fw")
            except:
                fw = None
            #### rules
            rules_str = udf.get("deterrers_rules") or "[]"
            rules = []
            try:
                rules_list = json.loads(rules_str)
                if isinstance(rules_list, list):
                    for rule_item in rules_list:
                        # Adjust this based on how HostBasedPolicy is constructed
                        if rule_item:
                            rules.append(rule_item)
            except (json.JSONDecodeError, ValueError, TypeError):
                rules = []
            #### comment
            try:
                comment = udf.get("comment")
            except:
                comment = None

            # get dns records
            dns_rcs = self.__get_linked_dns_records(host_id, ip)
            tagged_admins = self.__get_admins_of_host(host_id)
            #print(data)
            
            #print("//------------------DEBUG INFO------------------//")
            #print(f"Retrieved host info for IP {ipv4}: ID={host_id}, Name={name}, MAC={mac}, Status={status}, Service Profile={service_profile}, FW={fw}, Rules={rules}, Comment={comment}, DNS Records={dns_rcs}, Tagged Admins={tagged_admins}")  # Debugging line
            #print("//------------------DEBUG INFO END------------------// \n")
            
            return MyHost(
                entity_id=host_id,
                ipv4_addr=ip,
                mac_addr=mac,
                admin_names=set(tagged_admins),
                status=HostStatus(status) if status else HostStatus.EMPTY,
                name=name,
                dns_rcs=set(dns_rcs),
                service_profile=HostServiceProfile(service_profile) if service_profile else HostServiceProfile.EMPTY,
                fw=HostFW(fw) if fw else HostFW.EMPTY,
                host_based_policies=rules,
                comment=comment if comment else '',
            )
            
            #todo __get_linked_dns_records braucht erweiterungen um alle domain namen zu finden
            
        except Exception as e:
            logging.error(f"Error retrieving host info for IP {ipv4}: {e}")
            return None

    def __get_admins_of_host(self, host_id: int) -> list:
        """
        Queries the Proteus IPAM system for all tagged admins of a host.

        Args:
            host_id (int): Entity ID of the host in the Proteus IPAM system.

        Returns:
            list: Returns a list of admin rz-ids.
        """
        tagged_admins = []
        try:
            # Get tags linked to the address
            tags_resp = self.client.http_get(f"/addresses/{host_id}/tags")
            #print(f"Raw tags response for host ID {host_id}:", tags_resp)  # Debugging line
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
            # Get resource records linked to this address
            #This acutually dont work because the API v2 does not support this endpoint, we need to do a workaround by getting all records and filtering them by IP
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
            # Get tag by name
            tag_resp = self.client.http_get("/tags", params={"filter": f"name:'{admin_name}'"}) # Get the tag for the admin
            tags = tag_resp.get("data", []) # Extract the tag data
            if not tags:
                return []
            
            tag_id = tags[0].get("id") # Get the tag ID
            
            # Get parent department tag via helper (uses _links.up)
            department_name = self.get_department_to_admin(admin_name) # Get the department name for the admin
            parent_id = None
            if department_name:
                dep_resp = self.client.http_get("/tags", params={"filter": f"name:'{department_name}'"}) # Get the tag for the department
                parent_id = (dep_resp.get("data", [{}])[0] or {}).get("id") # Get the parent tag ID
            
            # Collect tag IDs to query (admin tag + parent department tag)
            tag_ids_to_query = [tag_id] # Start with the admin tag ID
            if parent_id:
                tag_ids_to_query.append(parent_id) # Add parent department tag ID if available
    
            # Get hosts for each tag
            for tid in tag_ids_to_query: # First query with filter for IPv4Address type, if it fails, fallback to unfiltered query and manual filtering
                try:
                    tagged_resp = self.client.http_get(
                        f"/tags/{tid}/taggedResources",
                        params={"filter": "type:'IPv4Address'", "limit": "10000"} # Try to filter for IPv4Address type directly in the API call
                    )
                    tagged_resources = tagged_resp.get("data", []) # Extract tagged resources from response
                except Exception:
                    logger.warning(f"API filtering for IPv4Address type failed for tag ID {tid}, falling back to unfiltered query and manual filtering.")
                    tagged_resp = self.client.http_get(
                        f"/tags/{tid}/taggedResources",
                        params={"limit": "10000"} # Get all tagged resources without type filter
                    )
                    tagged_resources = tagged_resp.get("data", []) # Extract tagged resources from response
                    # Manually filter for IPv4Address type since API filtering failed
                    tagged_resources = [res for res in tagged_resources if res.get("type") == "IPv4Address"]

                # Convert each tagged address to MyHost
                for addr in tagged_resources: # Iterate over tagged resources
                    ip = addr.get("address") # Get the IP address from the tagged resource
                    if ip:
                        host = self.get_host_info_from_ip(ip) # Get full host info using the existing method
                        if host:
                            hosts.append(host) # Add the host to the list if retrieval was successful
                        
        except Exception:
            logger.exception("Caught an unknown exception!")
        
        return hosts

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
            # Get the tag group by name
            tag_group_resp = self.client.http_get("/tagGroups", params={"filter": f"name:'{self.TAG_GROUP_NAME}'"})
            tag_group = tag_group_resp.get("data", [])
            if not tag_group:
                return names
            
            tag_group_id = tag_group[0].get("id")
            
            # Get all department tags (direct children of tag group)
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
            # Get tag by name
            tag_resp = self.client.http_get("/tags", params={"filter": f"name:'{admin_name}'"})# Get the tag for the admin
            tags = tag_resp.get("data", [])# Extract the tag data
            if not tags:
                return None            
            tag_id = tags[0].get("id") # Get the tag ID
            if not tag_id:
                return None
            tag_detail = self.client.http_get(f"/tags/{tag_id}") # Get tag details to find parent tag link
            tag_data = tag_detail.get("data", tag_detail) # Extract tag data
            up_link = (tag_data.get("_links", {}) or {}).get("up", {}).get("href") # Get the 'up' link to find parent tag
            if not up_link:
                return None
            parent_detail = self.client.http_get(up_link.replace("/api/v2", ""))# Get parent tag details
            parent_data = parent_detail.get("data", parent_detail) # Extract parent tag data
            return parent_data.get("name") # Return parent tag name as department name
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
            # Get the tag group by name - query /tagGroups, not /tags
            tag_group_resp = self.client.http_get("/tagGroups", params={"filter": f"name:'{self.TAG_GROUP_NAME}'"}) # Get the tag group for admins
            tag_group = tag_group_resp.get("data", [])  # Extract the tag group data
            if not tag_group:
                return set()
            
            tag_group_id = tag_group[0].get("id")
            
            # Get all department tags (direct children of tag group) using /tagGroups/{id}/tags
            dept_resp = self.client.http_get(f"/tagGroups/{tag_group_id}/tags") # Get department tags under the admin tag group
            departments = dept_resp.get("data", [])
            
            # For each department, get all admin tags (children of department)
            for dept in departments:
                dept_id = dept.get("id")
                # Get child tags of this department using /tags/{id}/tags
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
            # If admin already exists, do nothing
            if self.is_admin(admin_name):
                return False

            # Get tag group by name
            tag_group_resp = self.client.http_get("/tagGroups", params={"filter": f"name:'{self.TAG_GROUP_NAME}'"})
            tag_group = tag_group_resp.get("data", [])
            if not tag_group:
                return False

            tag_group_id = tag_group[0].get("id")

            # Get department tags (children of tag group)
            dept_resp = self.client.http_get(f"/tagGroups/{tag_group_id}/tags")
            departments = dept_resp.get("data", [])

            department_tag_id = None
            for dept in departments:
                if dept.get("name") == department_name:
                    department_tag_id = dept.get("id")
                    break

            if not department_tag_id:
                return False

            # Create admin tag under department
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
            # Query all admin names and check if this name is in the set
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
            
            # Get tag ID from admin name
            tag_resp = self.client.http_get("/tags", params={"filter": f"name:'{admin_name}'"}) # Get the tag for the admin
            tag_list = tag_resp.get("data", [])
            if not tag_list:
                return 404
            
            tag_id = tag_list[0].get("id") # Get the tag ID
            
            # Check if already tagged
            tags_resp = self.client.http_get(f"/addresses/{host_id}/tags") # Get current tags linked to the host
            host_tags = tags_resp.get("data", []) # Extract the list of tags linked to the host

            host_tag_ids = {t.get("id") for t in host_tags} # Create a set of tag IDs currently linked to the host for quick lookup
            if tag_id in host_tag_ids: # If the admin tag is already linked to the host, we can return success without doing anything
                return 200
            
            # Link tag to address
            self.client.http_post(f"/addresses/{host_id}/tags", json={"id": tag_id}) # Link the admin tag to the host address using the correct API v2 endpoint
            
            return 200
            
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

            # Check if already tagged
            tags_resp = self.client.http_get(f"/addresses/{host_id}/tags")
            host_tags = tags_resp.get("data", [])
            host_tag_ids = {t.get("id") for t in host_tags}

            if tag_id not in host_tag_ids:
                return 200

            # Unlink tag from address
            self.client.http_delete(f"/addresses/{host_id}/tags/{tag_id}")

            return 200

        except Exception:
            logger.exception(f"Couldn't remove tag '{admin_name}' from host {host.ipv4_addr}!")
            return 500

    def update_host_info(self, host: MyHost) -> bool:
        """
        Updates host information in the Proteus IPAM system (v2).

        Args:
            host (MyHost): Host instance that holds all the latest information.

        Returns:
            bool: Returns True on success and False on error.
        """
        # Validate host if possible
        if hasattr(host, "is_valid") and not host.is_valid():
            logger.error("Host not valid: %s", str(host))
            return False

        try:
            # Build rules list
            rules_list = []
            for policy in host.host_based_policies or []:
                if hasattr(policy, "to_string"):
                    rules_list.append(policy.to_string())
                else:
                    rules_list.append(policy)

            # Fetch current address to preserve required fields (e.g., state)
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

            payload = {
                "id": host.entity_id,
                "name": getattr(host, "name", None) or current_data.get("name"),
                "type": current_data.get("type") or "IPv4Address",
                "state": current_data.get("state"),
                "macAddress": current_data.get("macAddress"),
                "userDefinedFields": user_defined_fields,
            }

            self.client.http_put(f"/addresses/{host.entity_id}", json=payload)
            return True

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