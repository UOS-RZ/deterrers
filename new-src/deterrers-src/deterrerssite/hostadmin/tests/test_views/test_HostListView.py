from unittest.mock import patch, MagicMock, create_autospec

from django.test import TestCase
from django.urls import reverse
from myuser.models import MyUser

from hostadmin.core.host import MyHost


class MockInterface():

    def __enter__(self):
        return self
    
    def __exit__(self, *args):
        pass

    def get_hosts_of_admin(self, *args):
        return [MyHost(f'127.0.0.{i}', "00-11-22-AA-AA-AA", 'testUser', 'U') for i in range(30)]


@patch('hostadmin.views.ProteusIPAMInterface', MockInterface)
class HostListViewTestCase(TestCase):
    def login_user(self, username):
        self.client.login(username=username, password='TestPassword1234')

    @classmethod
    def setUpTestData(cls):

        test_user = MyUser.objects.create_user(
            username = 'testUser',
            email = 'testUser@uos.de',
            password = 'TestPassword1234'
        )

    
    def test_view_redirects_if_not_logged_in(self):
        response = self.client.get('/hostadmin/hosts/')
        self.assertRedirects(response, '/login/?next=/hostadmin/hosts/')

    def test_view_url_exists_at_desired_location(self):
        self.login_user('testUser')

        response = self.client.get('/hostadmin/hosts/')
        self.assertEqual(response.status_code, 200)

    def test_view_url_accessible_by_name(self):
        self.login_user('testUser')

        response = self.client.get(reverse('hosts_list'))
        self.assertEqual(response.status_code, 200)

    def test_view_uses_correct_template(self):
        self.login_user('testUser')

        response = self.client.get(reverse('hosts_list'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "hosts_list.html")

    def test_pagination_is_twenty(self):
        self.login_user('testUser')

        # test page 1
        response = self.client.get(reverse('hosts_list'))

        self.assertEqual(response.status_code, 200)
        self.assertTrue('is_paginated' in response.context)
        self.assertTrue(response.context['is_paginated'] == True)
        self.assertIsNotNone(response.context['hosts_list'])
        self.assertEqual(len(response.context['hosts_list']), 20)
        # test page 2
        response = self.client.get(reverse('hosts_list')+'?page=2')
        self.assertEqual(response.status_code, 200)
        self.assertTrue('is_paginated' in response.context)
        self.assertTrue(response.context['is_paginated'] == True)
        self.assertIsNotNone(response.context['hosts_list'])
        self.assertEqual(len(response.context['hosts_list']), 10)

