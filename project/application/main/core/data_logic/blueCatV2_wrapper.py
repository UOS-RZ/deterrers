# ─── External IPAM client library ────────────────────────────────────────────
# bluecat_libraries is the official Python SDK for BlueCat Address Manager (BAM).
# The apiv2 module wraps the REST API v2, available from BAM >= 9.3.
# The Client class handles session management (login/logout), URL construction
# and provides helper methods: http_get, http_post, http_put, http_delete.
from bluecat_libraries.address_manager.apiv2 import Client

import logging
import json
import ipaddress   # For validating and normalising IP addresses before passing them to the API
import socket      # Fallback for reverse DNS lookups if the IPAM API is unavailable

from main.core.data_logic.data_abstract import DataAbstract   # Abstract base class that defines the interface for every IPAM wrapper
from main.core.host import MyHost                              # Deterrers-internal host representation
from main.core.contracts import (HostStatus,           # Enum: UNREGISTERED, ACTIVE, BLOCKED ...
                                 HostServiceProfile,   # Enum: which services the host exposes (HTTP, SSH ...)
                                 HostFW)               # Enum: which firewall type protects the host
from main.core.rule_generator import HostBasedPolicy  # Represents a single host-based firewall rule

logger = logging.getLogger(__name__)


# ─── Data model in BlueCat IPAM ───────────────────────────────────────────────
# BlueCat BAM organises admin assignments in a two-level tag hierarchy:
#
#   TagGroup  "Deterrers Host Admins"
#   └── Tag   "Department of Computer Science"   ← Department tag
#       ├── Tag   "mueller"                      ← Admin tag (admin's username/ID)
#       └── Tag   "schmidt"
#   └── Tag   "Administration"
#       └── Tag   "huber"
#
# Hosts (IPv4Address objects in BAM) are linked to one or more admin tags.
# This mechanism tells Deterrers who is responsible for a given host.
#
# Deterrers-specific metadata (status, firewall type, rules, comment)
# is stored as User-Defined Fields (UDFs) on the IPv4Address object,
# because BAM has no native concept for these fields.

class ProteusV2IPAMWrapper(DataAbstract):
    """Wrapper for BlueCat IPAM REST API v2."""

    # Exact name of the tag group in BAM under which all Deterrers admin tags
    # are organised.  Must match the name configured in BAM exactly.
    TAG_GROUP_NAME = "Deterrers Host Admins"
    # BlueCat rejects address updates when these required UDFs are empty.
    # Only these known required fields get a fallback value; other UDFs are
    # left unchanged so that Deterrers does not silently modify unrelated data.
    REQUIRED_ADDRESS_UDF_DEFAULTS = {
        "admin_name": "N/A",
        "admin_email": "unknown@uni-osnabrueck.de",
        "admin_phone": "N/A",
    }

    def __init__(self, username: str, password: str, url: str) -> None:
        """Initialize the BlueCat IPAM v2 wrapper.

        Args:
            username (str): Username for BlueCat IPAM authentication.
            password (str): Password for BlueCat IPAM authentication.
            url (str): Base URL of the BlueCat IPAM API.
        """
        # Credentials and URL are stored in the base class (DataAbstract).
        # The password is accessible there via the protected attribute _password.
        super().__init__(username, password, url)
        # The client object is created lazily in __enter__ so that the class
        # can be instantiated safely without an active network connection.
        self.client = None
        # Cached tag group ID for "Deterrers Host Admins".
        # Fetching it costs one API call; caching avoids repeating that
        # call for every operation within the same session.
        self.__tag_group_id = None
        # Reserved for future caching of department tags (not used yet).
        self.__department_tags = None

    def __enter__(self):
        """Open a session to the BlueCat IPAM API v2.

        Returns:
            ProteusV2IPAMWrapper: Self reference for use in with-statements.
        """
        try:
            # The Client object handles session management and provides helper methods
            self.client = Client(self.url)
            # Login creates a session server-side and consumes a licence slot; it must succeed for any subsequent API calls to work.
            self.client.login(self.username, self._password)
            logger.info("Successfully connected to BlueCat IPAM API v2.")
            # enter_ok is read in __exit__ to decide whether a logout is
            # necessary (i.e. whether the login actually succeeded).
            self.enter_ok = True
        except Exception as e:
            logger.exception(f"Failed to connect to BlueCat IPAM API v2: {e}")
            self.enter_ok = False
        return self
    
    def __exit__(self, exc_type, exc_value, traceback):
        """Close the session to the BlueCat IPAM API v2."""
        # Only attempt logout if a session was actually established.
        if self.client and self.enter_ok:
            try:
                # Logout invalidates the session server-side and releases the licence slot.
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
        # Caching logic: if the ID has already been fetched during this session, return it directly.
        if self.__tag_group_id is not None:
            return self.__tag_group_id

        try:
            # Filter by exact name so that only the relevant tag group is rerurned.  The filter syntax is "name:'exact_name'".
            tag_group_resp = self.client.http_get("/tagGroups", params={"filter": f"name:'{self.TAG_GROUP_NAME}'"})
            # The response contains a "data" field which is a list of matching tag groups. 
            # We expect exactly one match; if there are multiple matches or no matches, we return None.
            tag_group = tag_group_resp.get("data", [])
            if tag_group:
                # Cache the ID for reuse within this session.
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
            # Validate and normalise the address before passing it to the API.
            ip_obj = ipaddress.IPv4Address(ipv4)
            # Get the host entity by filtering for the exact IP address.  The filter syntax is "address:'exact_ip'".  limit=1 is a pragmatic upper bound since IP addresses are unique in the IPAM; it also optimises performance by avoiding unnecessary data transfer.
            response_data = self.client.http_get("/addresses", params={"filter": f"address:'{ip_obj}'", "limit": 1})["data"]
            
            if not response_data or len(response_data) == 0:
                logger.warning(f"No host found for IP {ipv4}")
                return None
            
            data = response_data[0]
            
            # ── Extract required fields from the API response ──────────────────
            # Each field is caught individually so that a missing field does not
            # abort the entire host lookup.  Missing fields receive safe defaults
            # (None or empty string).
            try:
                # Internal BlueCat primary key of the IPv4Address object.
                # Required for all subsequent endpoints (tags, records, ...).
                host_id = data["id"]
            except KeyError:
                host_id = None
            try:
                # Free-text name assigned to this address in BAM.
                name = data["name"]
            except KeyError:
                name = ''
            try:
                # IP address as a string, as returned by BAM.
                ip = data["address"]
            except KeyError:
                ip = ''
            
            try:
                # MAC address (if maintained in BAM).
                # Encoded as a nested object {"address": "aa:bb:..."}.
                mac = data["macAddress"]["address"]
            except (KeyError, TypeError):
                mac = ''
            
            # ── User-Defined Fields (UDFs) ─────────────────────────────────────
            # UDFs are custom attributes defined in BAM for IPv4Address objects.
            # Deterrers uses them to store application-specific state without
            # modifying the BAM schema.
            udf = data.get("userDefinedFields", {})
            # deterrers_status: current registration/blocking status (HostStatus enum)
            status = udf.get("deterrers_status")
            # deterrers_service_profile: which service profile is assigned to the host
            service_profile = udf.get("deterrers_service_profile")
            # deterrers_fw: which firewall type protects the host
            fw = udf.get("deterrers_fw")
            
            # ── Parse firewall rules from JSON string ─────────────────────────
            # Host-based policies are stored as a JSON array of strings in a single UDF field 
            # Example value:  '["ALLOW tcp 443", "ALLOW tcp 80"]'
            rules_str = udf.get("deterrers_rules") or "[]"
            rules = []
            try:
                # Parse the JSON string into a list of rule strings.
                rules_list = json.loads(rules_str)
                if isinstance(rules_list, list):
                    for rule_item in rules_list:
                        if rule_item:
                            # from_string() parses the string back into a rule object;
                            # returns None if the format is invalid.
                            policy = HostBasedPolicy.from_string(rule_item)
                            if policy:
                                rules.append(policy)
            except (json.JSONDecodeError, ValueError, TypeError):
                # On a parse error, start with an empty rule list rather than
                # rejecting the host entirely.
                rules = []
            comment = udf.get("comment")

            # ── Load related data via separate API calls ───────────────────────
            # DNS names and admin tags are not stored directly on the
            # IPv4Address object in the BAM data model but are linked via
            # relations, so additional API calls are required.
            dns_rcs = self.__get_linked_dns_records(host_id)
            tagged_admins = self.__get_admins_of_host(host_id)
            
            my_host = MyHost(
                entity_id=int(host_id),
                ipv4_addr=ip,
                mac_addr=mac,
                admin_ids=set(tagged_admins),
                status=HostStatus(status) if status else HostStatus.UNREGISTERED, # Default to UNREGISTERED if the status UDF is not set or empty.
                name=name,
                dns_rcs=set(dns_rcs),
                service_profile=HostServiceProfile(service_profile) if service_profile else HostServiceProfile.EMPTY, # Default to EMPTY if the service profile UDF is not set or empty.
                fw=HostFW(fw) if fw else HostFW.EMPTY, # Default to EMPTY if the firewall UDF is not set or empty.
                host_based_policies=rules,
                comment=comment if comment else "",
            )

            # is_valid() checks that all required fields are populated.
            if my_host.is_valid():
                return my_host
            else:
                logger.warning("Host '%s' is not valid!", ipv4)
                return None
            
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
            # GET /addresses/{id}/tags returns all tag objects linked to this IPv4Address object.
            tags_resp = self.client.http_get(f"/addresses/{host_id}/tags")
            tags = tags_resp.get("data", [])
            
            for tag in tags:
                # The "name" of a tag corresponds to the admin's username/ID.
                # Tags without a name are skipped.
                tag_id = tag.get("name")
                if tag_id:
                    tagged_admins.append(tag_id)
                        
        except Exception:
            logger.exception("Caught an unknown exception!")

        return tagged_admins
    
    def __get_linked_dns_records(self, address_id: int) -> set[str]:
        """Query DNS records linked to an IPv4 address entity.

        Args:
            address_id (int): Entity ID of the IPv4 address in BlueCat.


        Returns:
            set[str]: Set of DNS names associated with the address.
        """
        dns_names = set()

        try:
            # GET /addresses/{id}/resourceRecords returns all DNS resource
            # records linked to this IP address.
            records_resp = self.client.http_get(f"/addresses/{address_id}/resourceRecords")
            for record in records_resp.get("data", []):
                rec_type = record.get("type")
                # Only HostRecord and ExternalHostRecord contain meaningful
                # fully qualified domain names (FQDNs).
                # Other record types (e.g. AliasRecord/CNAME) are skipped
                # because they do not represent a standalone hostname.
                if rec_type in {"HostRecord", "ExternalHostRecord"}:
                    # absoluteName holds the FQDN, e.g. "server.example.com".
                    # Falls back to the relative name if absoluteName is absent.
                    name = record.get("absoluteName") or record.get("name")
                    if name:
                        dns_names.add(name)
        except Exception:
            logger.exception(
                "Couldn't query linked DNS records for address id %s!",
                address_id,
            )


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
            # Resolve the admin tag by name (= admin username/ID).
            tag_resp = self.client.http_get("/tags", params={"filter": f"name:'{admin_name}'"})
            tags = tag_resp.get("data", [])
            if not tags:
                return []
            
            tag_id = tags[0].get("id")
            
            # ── Also consider the parent department tag ────────────────────────
            # A host can be linked either directly to the admin tag OR to the
            # parent department tag.  The latter is the case when a host is
            # managed by the whole department and not assigned to a specific admin.
            # Both tag IDs are therefore queried and their results merged.
            department_name = self.get_department_to_admin(admin_name)
            parent_id = None
            if department_name:
                dep_resp = self.client.http_get("/tags", params={"filter": f"name:'{department_name}'"})
                # Defensive access: get("data", [{}])[0] returns {} when the list
                # is empty so that .get("id") does not raise a TypeError.
                parent_id = (dep_resp.get("data", [{}])[0] or {}).get("id")
            
            # Build the list of tag IDs for which tagged resources will be queried.
            tag_ids_to_query = [tag_id]
            if parent_id:
                tag_ids_to_query.append(parent_id)
    
            for tid in tag_ids_to_query:
                # GET /tags/{id}/taggedResources returns all objects linked to
                # this tag.  The filter type:'IPv4Address' restricts results to
                # IP addresses and excludes other BAM objects (e.g. networks,
                # blocks). limit=10000 is a upper bound to avoid performance 
                # issues in case of an unexpectedly large number of tagged hosts.
                tagged_resp = self.client.http_get(
                    f"/tags/{tid}/taggedResources",
                    params={"filter": "type:'IPv4Address'", "limit": "10000"}
                )
                tagged_resources = tagged_resp.get("data", [])

                # Each tagged resource contains a nested "address" field with the IP address string.
                #  The host info is loaded for each IP and added to the result list.
                for addr in tagged_resources:
                    ip = addr.get("address")
                    if ip:
                        host = self.get_host_info_from_ip(ip)
                        if host:
                            hosts.append(host)
                        
        except Exception:
            logger.exception("Caught an unknown exception!")
        
        # ── Deduplicate results ───────────────────────────────────────────────
        # If a host is linked to both the admin tag and the department tag it
        # will appear in both result lists.  Deduplicate by IP address, which
        # is the unique key in the IPAM.
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
        Query public IPv6 addresses linked to a host's IPv4 address via
        shared HostRecords in the BlueCat IPAM API v2.

        Args:
            host (MyHost): Host instance for which IPv6 addresses are queried.

        Returns:
            set[str]: Set of public IPv6 address strings in exploded form.
        """
        try:
            ipv4_id = host.entity_id
            # Step 1: Fetch all HostRecords for this IPv4Address object.
            # A HostRecord in BAM can point to both an IPv4 AND an IPv6 address
            # (dual-stack DNS entry).  The shared HostRecord is the bridge to
            # the corresponding IPv6 addresses.
            records_resp = self.client.http_get(f"/addresses/{ipv4_id}/resourceRecords")
            all_addresses = set()
            for record in records_resp.get("data", []):
                # Only consider HostRecords – standalone AAAA records are not
                # linked to an IPv4 address.
                if record.get("type") != "HostRecord":
                    continue
                record_id = record.get("id")
                if not record_id:
                    continue
                # Step 2: Fetch all addresses linked to this HostRecord
                # (both IPv4 and IPv6).
                addr_resp = self.client.http_get(
                    f"/resourceRecords/{record_id}/addresses"
                )
                for addr in addr_resp.get("data", []):
                    address = addr.get("address")
                    if address:
                        all_addresses.add(address)

            # Step 3: Filter for IPv6 addresses and restrict to public ones.
            # is_private == True for: ::1, fc00::/7 (ULA), fe80::/10 (link-local), etc.
            # Only public IPv6 addresses are relevant for firewall rules.
            # The exploded form (full representation without "::") is used so
            # that firewall rules receive consistent address strings.
            ipv6_addrs = set()
            for ip in all_addresses:
                try:
                    ipv6 = ipaddress.IPv6Address(ip)
                    if not ipv6.is_private:
                        ipv6_addrs.add(ipv6.exploded)
                except ipaddress.AddressValueError:
                    # IPv4 strings raise AddressValueError in IPv6Address() → skip.
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
        names = []
        try:
            tag_group_id = self.__get_tag_group_id()
            if not tag_group_id:
                return names
            
            # GET /tagGroups/{id}/tags returns all direct child tags (one level
            # deep).  Since department tags are direct children of the tag group,
            # this call returns exactly the department names needed.
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
        """Get the department name for a given admin tag.

        Args:
            admin_name (str): Name of the admin tag.

        Returns:
            str | None: Department name or None if not found.
        """
        try:
            # Look up the admin tag by name. The filter syntax is "name:'exact_name'".
            tag_resp = self.client.http_get("/tags", params={"filter": f"name:'{admin_name}'"})
            tags = tag_resp.get("data", [])
            if not tags:
                return None
            tag_id = tags[0].get("id")
            if not tag_id:
                return None
            # Get the tag details to access the "_links" section, which contains the "up" link to the parent tag.
            tag_detail = self.client.http_get(f"/tags/{tag_id}")
            tag_data = tag_detail
            # The "up" link points to the parent tag (= department tag).
            # Structure: _links → up → href: "/api/v2/tags/{parent_id}"
            # If this link is absent, the tag has no parent (it is itself a
            # department tag or lives outside the expected hierarchy).
            up_link = (tag_data.get("_links", {}) or {}).get("up", {}).get("href")
            if not up_link:
                return None
            # Follow the "up" link to get the parent tag details, which contain the department name.
            parent_detail = self.client.http_get(up_link.replace("/api/v2", ""))
            return parent_detail.get("name")
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
            
            # First level: load all department tags under the tag group.
            dept_resp = self.client.http_get(f"/tagGroups/{tag_group_id}/tags")
            departments = dept_resp.get("data", [])
            
            for dept in departments:
                dept_id = dept.get("id")
                # Second level: load all admin tags under this department tags.
                # GET /tags/{dept_id}/tags returns the direct child tags.
                admin_resp = self.client.http_get(f"/tags/{dept_id}/tags")
                admin_tags = admin_resp.get("data", [])
                for admin in admin_tags: 
                    admin_name = admin.get("name")
                    if admin_name:
                        admin_tag_names.append(admin_name)
            
            return set(admin_tag_names)  # set() removes any accidental duplicates
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
            # Idempotency check: if the admin tag already exists, abort to
            # avoid creating duplicates in BAM.  Returns False (no error,
            # but nothing was done).
            if self.is_admin(admin_name):
                return False

            tag_group_id = self.__get_tag_group_id()
            if not tag_group_id:
                return False

            # Load all department tags and find the matching one.
            # No name filter is applied here because the department list is
            # typically small and can be fetched in a single call.
            dept_resp = self.client.http_get(f"/tagGroups/{tag_group_id}/tags")
            departments = dept_resp.get("data", [])

            department_tag_id = None
            for dept in departments:
                if dept.get("name") == department_name:
                    department_tag_id = dept.get("id")
                    break

            if not department_tag_id:
                # The specified department does not exist in BAM.
                return False

            # POST /tags/{parent_id}/tags creates a new child tag under the
            # department.  BAM returns the newly created tag object with its ID;
            # we use the ID as the success indicator.
            response = self.client.http_post(f"/tags/{department_tag_id}/tags", json={"name": admin_name})
            if response and isinstance(response, dict) and response.get("id"):
                return True
            else:
                logger.error("Failed to create tag for admin %s!", admin_name)
                return False

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
            # Delegates to get_all_admin_names() to load the full set of admin
            # tags, then checks membership via a set lookup (O(1)).
            # Trade-off: loads all admin names even when checking just one.
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
            
            # Resolve the tag ID for the given admin name.
            tag_resp = self.client.http_get("/tags", params={"filter": f"name:'{admin_name}'"})
            tag_list = tag_resp.get("data", [])
            if not tag_list:
                # Tag does not exist in the IPAM (admin was never created).
                return 404
            
            tag_id = tag_list[0].get("id")
            
            # Idempotency check: is the tag already linked to the host?
            # Posting a duplicate tag link would cause an error in BAM.
            tags_resp = self.client.http_get(f"/addresses/{host_id}/tags")
            host_tags = tags_resp.get("data", [])

            host_tag_ids = {t.get("id") for t in host_tags}
            if tag_id in host_tag_ids:
                # Tag is already set – report success without a write call.
                return 200
            
            # POST /addresses/{id}/tags links the tag to the address.
            # The body contains only the tag ID; BAM handles the link logic.
            response = self.client.http_post(f"/addresses/{host_id}/tags", json={"id": tag_id})
            if response and isinstance(response, dict) and response.get("id"):
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

            # Resolve the tag ID for the given admin name.
            tag_resp = self.client.http_get("/tags", params={"filter": f"name:'{admin_name}'"})
            tag_list = tag_resp.get("data", [])
            if not tag_list:
                return 404

            tag_id = tag_list[0].get("id")

            # Check whether the tag is actually linked to the host.
            tags_resp = self.client.http_get(f"/addresses/{host_id}/tags")
            host_tags = tags_resp.get("data", [])
            host_tag_ids = {t.get("id") for t in host_tags}

            if tag_id not in host_tag_ids:
                # Tag was not set – nothing to do, still report success.
                return 200

            # DELETE /addresses/{host_id}/tags/{tag_id} removes the link.
            # (HTTP 204 No Content).  Any non-"" value indicates an error.
            response = self.client.http_delete(f"/addresses/{host_id}/tags/{tag_id}")
            if response is not None:
                # On success, also update the locally cached state of the host
                # object so that subsequent calls see consistent data without
                # querying the IPAM again.
                host.admin_ids.remove(admin_name)
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
        # Validation check: ensure that the host object has all required fields
        if hasattr(host, "is_valid") and not host.is_valid():
            logger.error("Host not valid: %s", str(host))
            return False

        try:
            # ── Serialise firewall rules ───────────────────────────────────────
            # HostBasedPolicy objects are converted to strings and stored as a
            # JSON array in a single UDF field.
            # Background: BAM does not support array fields, so the list is
            # stored as a serialised JSON string in a text UDF.
            rules_list = []
            for policy in host.host_based_policies or []:
                if hasattr(policy, "to_string"):
                    rules_list.append(policy.to_string())
                else:
                    rules_list.append(policy)

            # ── Read-before-Write: load current state from BAM ────────────────
            # BlueCat API v2 expects a full object on PUT, not a partial update.
            # That means we first read the current address and then build the
            # outgoing payload from that state.
            current_resp = self.client.http_get(f"/addresses/{host.entity_id}")
            current_data = current_resp
            current_udf = current_data.get("userDefinedFields") or {}

            # Start with the current UDFs exactly as stored in BAM.
            user_defined_fields = dict(current_udf)

            # Only fill in the known required UDFs when they are empty.
            # This avoids changing unrelated custom fields just because their
            # current value happens to be None or an empty string.
            for field_name, default_value in self.REQUIRED_ADDRESS_UDF_DEFAULTS.items():
                if not user_defined_fields.get(field_name):
                    user_defined_fields[field_name] = default_value

            # Overwrite only the fields that Deterrers is responsible for.
            user_defined_fields["deterrers_service_profile"] = (
                host.get_service_profile_display()
                if hasattr(host, "get_service_profile_display")
                else str(getattr(host, "service_profile", ""))
            )
            user_defined_fields["deterrers_fw"] = (
                host.get_fw_display()
                if hasattr(host, "get_fw_display")
                else str(getattr(host, "fw", ""))
            )
            user_defined_fields["deterrers_status"] = (
                host.get_status_display()
                if hasattr(host, "get_status_display")
                else str(getattr(host, "status", ""))
            )
            user_defined_fields["deterrers_rules"] = json.dumps(rules_list)
            user_defined_fields["comment"] = getattr(host, "comment", "") or ""

            # The PUT payload must include all top-level fields required by the
            # API; missing required fields result in HTTP 400/422.
            # type and state are read from the current state because Deterrers
            # does not manage those fields itself.
            payload = {
                "id": host.entity_id,
                "name": getattr(host, "name", None) or current_data.get("name"),
                "type": current_data.get("type") or "IPv4Address",
                "state": current_data.get("state"),
                "macAddress": current_data.get("macAddress"),
                "userDefinedFields": user_defined_fields,
            }

            # PUT /addresses/{id} writes the complete new state.
            # On success BAM returns the updated object including its ID.
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
            # GET /users with a name filter – on a match the API returns a
            # data array containing at least one object.
            resp = self.client.http_get("/users", params={"filter": f"name:'{username}'"})
            users = resp.get("data", [])
            return len(users) > 0
        except Exception:
            logger.exception("Couldn't query IPAM whether user exists!")
            return None