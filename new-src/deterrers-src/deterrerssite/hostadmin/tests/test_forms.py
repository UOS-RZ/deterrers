from django.test import TestCase

from hostadmin.forms import ChangeHostDetailForm

class ChangeHostDetailFormTestCase(TestCase):

    @classmethod
    def setUpTestData(cls):
        pass

    def setUp(self):
        pass

    def test_field_lables(self):
        test_form = ChangeHostDetailForm()

        self.assertEqual(test_form.fields['service_profile'].label, 'Service Profile')
        self.assertEqual(test_form.fields['fw'].label, 'Host-based Firewall')
        
