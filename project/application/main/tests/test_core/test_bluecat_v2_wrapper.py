from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import Mock, patch

from django.template.loader import render_to_string
from django.test import SimpleTestCase

from main import views
from main.api import api_views
from main.api.serializers import MyHostSerializer
from main.core.data_logic.blueCatV2_wrapper import ProteusV2IPAMWrapper
from main.core.data_logic.data_abstract import DataAbstract


class FakeBlueCatClient:
    """Model real tag links: deleting an inherited link is an error."""

    def __init__(self):
        self.links = {10}
        self.writes = []
        self.fail_add = False
        self.fail_delete = False
        self.departments = [
            {"id": 10, "name": "Department", "_embedded": {"tags": [
                {"id": 11, "name": "alice"},
                {"id": 12, "name": "bob"},
            ]}},
            {"id": 20, "name": "Other", "_embedded": {"tags": [
                {"id": 21, "name": "alice"},
            ]}},
            {"id": 30, "name": "Empty"},
        ]

    def http_get(self, path, params=None):
        if path == "/tagGroups":
            return {"data": [
                {"id": 2, "name": "Unrelated"},
                {"id": 1, "name": "Deterrers Host Admins"},
            ]}
        if path == "/tagGroups/1/tags":
            return {"data": self.departments}
        if path == "/addresses":
            return {"data": [{"id": 99, "address": "192.0.2.1"}]}
        if path == "/addresses/99/resourceRecords":
            return {"data": []}
        if path == "/addresses/99/tags":
            return {"data": [{"id": tag_id} for tag_id in self.links]}
        raise AssertionError(f"Unexpected GET: {path}")

    def http_post(self, path, json):
        if path != "/addresses/99/tags":
            raise AssertionError(f"Unexpected POST: {path}")
        if self.fail_add:
            return None
        tag_id = json["id"]
        self.links.add(tag_id)
        self.writes.append(("add", tag_id))
        return {"id": tag_id}

    def http_delete(self, path):
        tag_id = int(path.rsplit("/", 1)[1])
        if self.fail_delete:
            return None
        self.links.remove(tag_id)
        self.writes.append(("delete", tag_id))
        return ""


class BlueCatV2AdminTest(SimpleTestCase):
    def setUp(self):
        self.ipam = ProteusV2IPAMWrapper("user", "password", "url")
        self.ipam.client = FakeBlueCatClient()
        self.client = self.ipam.client
        self.host = self.load_host({10})

    def load_host(self, links):
        self.client.links = set(links)
        host = self.ipam.get_host_info_from_ip("192.0.2.1")
        self.assertIsNotNone(host)
        return host

    def test_department_expands_without_extending_host_or_serializer(self):
        self.assertEqual(self.host.admin_ids, {"Department", "alice", "bob"})
        self.assertEqual(self.ipam.get_direct_admin_names(self.host), {"Department"})
        self.assertFalse(hasattr(self.host, "direct_admin_tags"))
        data = MyHostSerializer(self.host).data
        self.assertEqual(set(data["admin_ids"]), self.host.admin_ids)
        self.assertNotIn("direct_admin_tags", data)

    def test_foreign_tags_are_ignored_and_not_removed(self):
        host = self.load_host({10, 999})
        self.assertEqual(host.admin_ids, {"Department", "alice", "bob"})
        for name in host.admin_ids.copy():
            self.assertEqual(self.ipam.remove_admin_from_host(name, host), 200)
        self.assertEqual(self.client.links, {999})
        self.assertEqual(host.admin_ids, set())

    def test_inherited_remove_is_noop(self):
        self.assertEqual(self.ipam.remove_admin_from_host("alice", self.host), 200)
        self.assertEqual(self.client.writes, [])
        self.assertEqual(self.host.admin_ids, {"Department", "alice", "bob"})

    def test_department_remove_preserves_other_sources(self):
        for links, expected in [
            ({10}, set()),
            ({10, 11}, {"alice"}),
            ({10, 20}, {"Other", "alice"}),
        ]:
            with self.subTest(links=links):
                host = self.load_host(links)
                self.assertEqual(self.ipam.remove_admin_from_host("Department", host), 200)
                self.assertEqual(host.admin_ids, expected)
                self.assertEqual(self.client.links, links - {10})

    def test_removing_direct_user_preserves_department_access(self):
        host = self.load_host({10, 11})
        self.assertEqual(self.ipam.remove_admin_from_host("alice", host), 200)
        self.assertEqual(host.admin_ids, {"Department", "alice", "bob"})
        self.assertEqual(self.client.links, {10})

    def test_remove_unlinks_all_direct_ids_with_same_name(self):
        host = self.load_host({11, 21})
        self.assertEqual(self.ipam.remove_admin_from_host("alice", host), 200)
        self.assertEqual(self.client.links, set())
        self.assertEqual(host.admin_ids, set())

    def test_add_inherited_user_creates_direct_link(self):
        self.assertEqual(self.ipam.add_admin_to_host("alice", self.host), 200)
        self.assertEqual(self.client.links, {10, 11})
        self.assertEqual(self.host.admin_ids, {"Department", "alice", "bob"})
        self.assertEqual(self.ipam.add_admin_to_host("alice", self.host), 200)
        self.assertEqual(self.client.writes, [("add", 11)])

    def test_add_department_expands_admins(self):
        host = self.load_host(set())
        self.assertEqual(self.ipam.add_admin_to_host("Department", host), 200)
        self.assertEqual(host.admin_ids, {"Department", "alice", "bob"})

    def test_failed_mutations_keep_host_state(self):
        self.client.fail_add = self.client.fail_delete = True
        self.assertEqual(self.ipam.add_admin_to_host("alice", self.host), 500)
        self.assertEqual(self.ipam.remove_admin_from_host("Department", self.host), 500)
        self.assertEqual(self.client.links, {10})
        self.assertEqual(self.host.admin_ids, {"Department", "alice", "bob"})

    def test_replace_department_with_member_adds_before_delete(self):
        self.assertEqual(self.ipam.set_host_admins(self.host, {"alice"}), 200)
        self.assertEqual(self.client.writes, [("add", 11), ("delete", 10)])
        self.assertEqual(self.host.admin_ids, {"alice"})

    def test_noop_update_does_not_materialize_inherited_users(self):
        self.assertEqual(self.ipam.set_host_admins(self.host, self.host.admin_ids.copy()), 200)
        self.assertEqual(self.client.writes, [])

    def test_update_preserves_explicit_link_alongside_department(self):
        host = self.load_host({10, 11})
        self.assertEqual(self.ipam.set_host_admins(host, {"Department", "alice"}), 200)
        self.assertEqual(self.client.links, {10, 11})
        self.assertEqual(self.client.writes, [])

    def test_replacement_department_covers_shared_member(self):
        self.assertEqual(self.ipam.set_host_admins(self.host, {"Other", "alice"}), 200)
        self.assertEqual(self.client.writes, [("add", 20), ("delete", 10)])
        self.assertEqual(self.host.admin_ids, {"Other", "alice"})

    def test_empty_department_remains_direct(self):
        self.assertEqual(self.ipam.set_host_admins(self.host, {"Empty"}), 200)
        self.assertEqual(self.client.links, {30})
        self.assertEqual(self.host.admin_ids, {"Empty"})

    def test_invalid_updates_do_not_write(self):
        for names, code in [(set(), 400), ({"unknown"}, 404)]:
            with self.subTest(names=names):
                self.assertEqual(self.ipam.set_host_admins(self.host, names), code)
                self.assertEqual(self.client.links, {10})
                self.assertEqual(self.client.writes, [])

    def test_failed_add_stops_before_removing_department(self):
        self.client.fail_add = True
        self.assertEqual(self.ipam.set_host_admins(self.host, {"alice"}), 500)
        self.assertEqual(self.client.links, {10})
        self.assertEqual(self.client.writes, [])

    def test_failed_read_stops_update(self):
        with patch.object(self.client, "http_get", side_effect=RuntimeError("unavailable")):
            with self.assertLogs("main.core.data_logic.blueCatV2_wrapper", level="ERROR"):
                self.assertEqual(self.ipam.set_host_admins(self.host, {"alice"}), 500)
        self.assertEqual(self.client.writes, [])

    def test_template_only_offers_removable_direct_names(self):
        for links, button_count in [({10}, 0), ({10, 11}, 2), ({11, 21}, 0)]:
            with self.subTest(links=links):
                host = self.load_host(links)
                html = render_to_string("host/general.html", {
                    "host_detail": host,
                    "host_ipv4": "192.0.2.1",
                    "direct_admins": self.ipam.get_direct_admin_names(host),
                    "can_update": True,
                })
                self.assertEqual(html.count(">Remove</button>"), button_count)
                self.assertIn("alice", html)
                self.assertNotIn("/bob/", html)

    def request(self, names=None):
        return SimpleNamespace(
            user=SimpleNamespace(username="alice", is_authenticated=True),
            method="POST",
            data={"ipv4_addr": "192.0.2.1", "admin_ids": names or ["alice"]},
        )

    def view_context(self, module, ipam=None):
        """Use real views and V2 methods; replace auth and external services."""
        ipam = ipam or self.ipam
        stack = ExitStack()
        wrapper_class = stack.enter_context(patch.object(module, "IPAMWrapper"))
        wrapper_class.return_value.__enter__.return_value = ipam
        ipam.enter_ok = True
        stack.enter_context(patch.object(
            module, "get_object_or_404", return_value=self.request().user,
        ))
        stack.enter_context(patch.object(module, "available_actions", return_value={
            "can_update": True, "can_remove": True,
        }))
        stack.enter_context(patch.object(ipam, "is_admin", return_value=True))
        stack.enter_context(patch.object(ipam, "update_host_info", return_value=True))
        return stack

    def test_api_patch_calls_v2_logic(self):
        with self.view_context(api_views):
            response = getattr(api_views, "__update_host")(self.request())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.client.writes, [("add", 11), ("delete", 10)])

    def test_api_patch_propagates_failed_write(self):
        self.client.fail_add = True
        with self.view_context(api_views):
            response = getattr(api_views, "__update_host")(self.request())
        self.assertEqual(response.status_code, 500)
        self.assertEqual(self.client.writes, [])

    def test_unchanged_api_delete_removes_only_real_links(self):
        with self.view_context(api_views):
            response = getattr(api_views, "__remove_host")(self.request())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.client.writes, [("delete", 10)])
        self.assertEqual(self.client.links, set())

    def test_unchanged_html_delete_removes_only_real_links(self):
        with self.view_context(views):
            response = views.remove_host(self.request(), "192.0.2.1")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.client.writes, [("delete", 10)])
        self.assertEqual(self.client.links, set())

    def test_remove_view_rejects_inherited_and_last_direct_admin(self):
        for name in ["alice", "Department"]:
            with (
                self.subTest(name=name),
                self.view_context(views),
                patch.object(views, "messages"),
            ):
                response = views.remove_admin_from_host_view(self.request(), "192.0.2.1", name)
                self.assertEqual(response.status_code, 302)
                self.assertEqual(self.client.writes, [])

    def test_detail_view_passes_direct_names_to_template(self):
        request = self.request()
        request.method = "GET"
        with self.view_context(views), patch.object(views, "render") as render:
            views.host_detail_view(request, "192.0.2.1")
        context = render.call_args.args[2]
        self.assertEqual(context["direct_admins"], {"Department"})
        self.assertEqual(context["host_detail"].admin_ids, {"Department", "alice", "bob"})

    def legacy_ipam(self):
        ipam = Mock(spec=DataAbstract)
        ipam.get_host_info_from_ip.return_value = self.load_host({11, 12})
        ipam.get_department_names.return_value = []
        ipam.add_admin_to_host.return_value = 200
        ipam.remove_admin_from_host.return_value = 200
        return ipam

    def test_legacy_detail_view_uses_existing_admin_ids(self):
        ipam = self.legacy_ipam()
        request = self.request()
        request.method = "GET"
        with self.view_context(views, ipam), patch.object(views, "render") as render:
            views.host_detail_view(request, "192.0.2.1")
        self.assertEqual(render.call_args.args[2]["direct_admins"], {"alice", "bob"})

    def test_legacy_api_patch_keeps_existing_path(self):
        ipam = self.legacy_ipam()
        with self.view_context(api_views, ipam):
            response = getattr(api_views, "__update_host")(self.request())
        self.assertEqual(response.status_code, 200)
        ipam.add_admin_to_host.assert_not_called()
        ipam.remove_admin_from_host.assert_called_once_with(
            "bob", ipam.get_host_info_from_ip.return_value,
        )

    def test_remove_view_allows_direct_user_with_department_remaining(self):
        self.client.links = {10, 11}
        with self.view_context(views), patch.object(views, "messages"):
            response = views.remove_admin_from_host_view(
                self.request(), "192.0.2.1", "alice",
            )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.client.links, {10})
        self.assertEqual(self.client.writes, [("delete", 11)])
