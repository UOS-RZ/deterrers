from unittest.mock import patch, MagicMock

from django.test import TestCase
from django.urls import reverse
from myuser.models import MyUser
from hostadmin.core.host import MyHost


mock_host = MyHost("131_17_22_11".replace('_', '.'), "00-11-22-AA-AA-AA", ['testUser'], 'U') 

class MockInterface():

    def __enter__(self):
        return self
    
    def __exit__(self, *args):
        pass

    def get_hosts_of_admin(self, **args):
        return [MyHost(f'127.0.0.{i}', "00-11-22-AA-AA-AA", 'testUser', 'U') for i in range(30)]

    def get_host_info_from_ip(self, admin_ids):
        return mock_host


@patch('hostadmin.views.ProteusIPAMInterface', MockInterface)
class HostDetailViewTestCase(TestCase):

    test_username = 'testUser'
    test_password = 'TestPassword1234'

    def login_user(self, username, password):
        self.client.login(username=username, password=password)

    @classmethod
    def setUpTestData(cls):
        pass

    def setUp(self):

        test_user = MyUser.objects.create_user(
            username = self.test_username,
            email = 'testUser@uos.de',
            password = self.test_password
        )

        global mock_host 
        mock_host = MyHost("131_17_22_11".replace('_', '.'), "00-11-22-AA-AA-AA", ['testUser'], 'U')

    def test_view_redirects_if_not_logged_in(self):
        response = self.client.get('/hostadmin/host/131_17_22_11/')
        self.assertRedirects(response, '/login/?next=/hostadmin/host/131_17_22_11/')
    
    def test_view_url_exists_at_desired_location(self):
        self.login_user(self.test_username, self.test_password)

        response = self.client.get('/hostadmin/host/131_17_22_11/')
        self.assertEqual(response.status_code, 200)

    def test_view_url_accessible_by_name(self):
        self.login_user(self.test_username, self.test_password)

        response = self.client.get(reverse('host_detail', args=['131_17_22_11',]))
        self.assertEqual(response.status_code, 200)

    def test_view_uses_correct_template(self):
        self.login_user(self.test_username, self.test_password)

        response = self.client.get(reverse('host_detail', args=['131_17_22_11',]))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "host_detail.html")

    # test behaviour

    def test_view_can_update_context_flag(self):
        self.login_user(self.test_username, self.test_password)

        response = self.client.get(reverse('host_detail', args=['131_17_22_11',]))
        self.assertTrue('can_update' in response.context)
        self.assertTrue(response.context['can_update'] is True)


    def test_view_cannot_update_context_flag(self):
        self.login_user(self.test_username, self.test_password)

        mock_host.status = 'R'
        response = self.client.get(reverse('host_detail', args=['131_17_22_11',]))
        self.assertTrue('can_update' in response.context)
        self.assertTrue(response.context['can_update'] is False)
        

    def test_view_can_register_context_flag(self):
        self.login_user(self.test_username, self.test_password)

        for sp in ['H', 'S', 'M']:
            for fw in ['A', 'B']:
                mock_host.service_profile = sp
                mock_host.fw = fw
                response = self.client.get(reverse('host_detail', args=['131_17_22_11',]))
                self.assertTrue('can_register' in response.context)
                self.assertTrue(response.context['can_register'] is True)

    def test_view_cannot_register_context_flag(self):
        self.login_user(self.test_username, self.test_password)

        combs = [
            ('', ''),
            ('H', ''),
            ('S', ''),
            ('M', ''),
            ('', 'A'),
            ('', 'B'),
        ]
        for sp, fw in combs:
            mock_host.service_profile = sp
            mock_host.fw = fw
            response = self.client.get(reverse('host_detail', args=['131_17_22_11',]))
            self.assertTrue('can_register' in response.context)
            self.assertTrue(response.context['can_register'] is False)

    def test_view_can_scan_context_flag(self):
        self.login_user(self.test_username, self.test_password)

        for s in ['U', 'B', 'O']:
            mock_host.status = s
            for sp in ['H', 'S', 'M']:
                for fw in ['A', 'B']:
                    mock_host.service_profile = sp
                    mock_host.fw = fw
                    self.assertTrue(mock_host.is_valid())
                    
                    response = self.client.get(reverse('host_detail', args=['131_17_22_11',]))
                    self.assertTrue('can_scan' in response.context, msg=f"{response.context}")
                    self.assertTrue(response.context['can_scan'] is True)

    def test_view_cannot_scan_context_flag(self):
        self.login_user(self.test_username, self.test_password)

        # should not be able to scan when under review
        mock_host.status = 'R'
        response = self.client.get(reverse('host_detail', args=['131_17_22_11',]))
        self.assertTrue('can_scan' in response.context)
        self.assertTrue(response.context['can_scan'] is False)

        for s in ['U', 'B', 'O']:
            mock_host.status = s
            combs = [
                ('', ''),
                ('H', ''),
                ('S', ''),
                ('M', ''),
                ('', 'A'),
                ('', 'B'),
            ]
            for sp, fw in combs:
                mock_host.service_profile = sp
                mock_host.fw = fw
                response = self.client.get(reverse('host_detail', args=['131_17_22_11',]))
                self.assertTrue('can_scan' in response.context)
                self.assertTrue(response.context['can_scan'] is False)
            

    def test_view_other_host_forbidden(self):
        test_user = MyUser.objects.create_user(
            username = "Hackerman",
            email = 'hackerman@uos.de',
            password = "P455W0RD"
        )
        self.login_user("Hackerman", "P455W0RD")

        response = self.client.get(reverse('host_detail', args=['131_17_22_11',]))
        self.assertEqual(response.status_code, 404)

    def test_view_invalid_host(self):
        global mock_host
        mock_host = MyHost('127.0.0.1', "00-11-22-AA-AA-AA", [self.test_username], '??')

        self.login_user(self.test_username, self.test_password)

        response = self.client.get(reverse('host_detail', args=['127_0_0_1',]))
        self.assertEqual(response.status_code, 404)
