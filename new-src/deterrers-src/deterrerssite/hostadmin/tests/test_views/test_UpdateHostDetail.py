from unittest.mock import patch, MagicMock

from django.test import TestCase
from django.urls import reverse
from myuser.models import MyUser
from hostadmin.core.host import MyHost



mock_host = MyHost("131_17_22_11".replace('_', '.'), "00-11-22-AA-AA-AA", ['testUser'], 'U')
mock_ret = True

class MockInterface():

    def __enter__(self):
        return self
    
    def __exit__(self, *args):
        pass

    def get_hosts_of_admin(self, **args):
        return [MyHost(f'127.0.0.{i}', 'testUser', 'U') for i in range(30)]

    def get_host_info_from_ip(self, admin_ids):
        return mock_host

    def update_host_info(self, host):
        return mock_ret


@patch('hostadmin.views.ProteusIPAMInterface', MockInterface)
class UpdateHostDetailTestCase(TestCase):

    test_username = 'testUser'
    test_password = 'TestPassword1234'

    def login_user(self, username, password):
        self.client.login(username=username, password=password)

    @classmethod
    def setUpTestData(cls):
        pass

    def setUp(self):
        global mock_host
        mock_host = MyHost("131_17_22_11".replace('_', '.'), "00-11-22-AA-AA-AA", [self.test_username], 'U')
        global mock_ret
        mock_ret = True

        test_user = MyUser.objects.create_user(
            username = self.test_username,
            email = 'testUser@uos.de',
            password = self.test_password
        )

    # standard view infrastructure tests

    def test_redirect_if_not_logged_in(self):
        response = self.client.get('/hostadmin/host/131_17_22_11/update/')
        self.assertRedirects(response, '/login/?next=/hostadmin/host/131_17_22_11/update/')
    
    def test_view_url_exists_at_desired_location(self):
        self.login_user(self.test_username, self.test_password)

        response = self.client.get('/hostadmin/host/131_17_22_11/update/')
        self.assertEqual(response.status_code, 200)

    def test_view_url_accessible_by_name(self):
        self.login_user(self.test_username, self.test_password)

        response = self.client.get(reverse('update_host_detail', args=['131_17_22_11',]))
        self.assertEqual(response.status_code, 200)

    def test_view_uses_correct_template(self):
        self.login_user(self.test_username, self.test_password)

        response = self.client.get(reverse('update_host_detail', args=['131_17_22_11',]))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "update_host_detail.html")

    # behavioral view tests

    def test_view_other_host_forbidden(self):
        test_user = MyUser.objects.create_user(
            username = "Hackerman",
            email = 'hackerman@uos.de',
            password = "P455W0RD"
        )
        self.login_user("Hackerman", "P455W0RD")

        response = self.client.get(reverse('update_host_detail', args=['131_17_22_11',]))
        self.assertEqual(response.status_code, 404)

    def test_view_update_other_host_forbidden(self):
        test_user = MyUser.objects.create_user(
            username = "Hackerman",
            email = 'hackerman@uos.de',
            password = "P455W0RD"
        )
        self.login_user("Hackerman", "P455W0RD")

        response = self.client.post(reverse('update_host_detail', args=['131_17_22_11',]))
        self.assertEqual(response.status_code, 404)

    def test_view_update_and_redirect(self):
        self.login_user(self.test_username, self.test_password)

        response = self.client.post(reverse('update_host_detail', args=['131_17_22_11',]))
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('host_detail', args=['131_17_22_11',]))

    def test_view_invalid_fw_update_error(self):
        self.login_user(self.test_username, self.test_password)

        response = self.client.post(reverse('update_host_detail', args=['131_17_22_11',]), {'fw': '??'})
        self.assertEqual(response.status_code, 200)
        self.assertFormError(response, 'form', 'fw', 'Select a valid choice. ?? is not one of the available choices.')
