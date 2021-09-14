import json
import os
from uuid import uuid4
from unittest import TestCase

from ossindex.model import OssIndexComponent, Vulnerability

FIXTURES_DIRECTORY = os.path.join(os.path.dirname(__file__), 'fixtures')


class TestModel(TestCase):

    def test_response_parse_no_vulnerabilities(self):
        with open(os.path.join(FIXTURES_DIRECTORY, 'oss-index-response-no-vulnerabilities.json'),
                  'r') as expected_response:
            json_response = json.loads(expected_response.read())

            self.assertEqual(len(json_response), 1, 'More than one component parsed!')

            oic = OssIndexComponent.from_json(json_response[0])
            self.assertIsInstance(oic, OssIndexComponent)
            self.assertFalse(oic.has_known_vulnerabilities())

        expected_response.close()

    def test_response_one_vulnerability(self):
        with open(os.path.join(FIXTURES_DIRECTORY, 'oss-index-response-1-vulnerability.json'),
                  'r') as expected_response:
            json_response = json.loads(expected_response.read())

            self.assertEqual(len(json_response), 1, 'More than one component parsed!')

            oic = OssIndexComponent.from_json(json_response[0])
            self.assertIsInstance(oic, OssIndexComponent)
            self.assertTrue(oic.has_known_vulnerabilities())
            self.assertEqual(len(oic.get_vulnerabilities()), 1)

        expected_response.close()

    def test_max_cvss_score_1(self):
        vulns = [
            Vulnerability(
                id=str(uuid4()), display_name='Test Vuln 1', title='Test Vuln 1', cvss_score=9.0
            ),
            Vulnerability(
                id=str(uuid4()), display_name='Test Vuln 2', title='Test Vuln 2', cvss_score=5.0
            )
        ]
        oic = OssIndexComponent(
            coordinates='test@1.0.0', description='Test', oss_index_reference_url='https://test.com',
            vulnerabilities=vulns
        )
        self.assertEqual(len(oic.get_vulnerabilities()), 2)
        self.assertEqual(oic.get_max_cvss_score(), 9.0)

    def test_max_cvss_score_2(self):
        vulns = [
            Vulnerability(
                id=str(uuid4()), display_name='Test Vuln 2', title='Test Vuln 2', cvss_score=5.0
            ),
            Vulnerability(
                id=str(uuid4()), display_name='Test Vuln 1', title='Test Vuln 1', cvss_score=9.5
            ),
            Vulnerability(
                id=str(uuid4()), display_name='Test Vuln 3', title='Test Vuln 3', cvss_score=1.5
            )
        ]
        oic = OssIndexComponent(
            coordinates='test@1.0.0', description='Test', oss_index_reference_url='https://test.com',
            vulnerabilities=vulns
        )
        self.assertEqual(len(oic.get_vulnerabilities()), 3)
        self.assertEqual(oic.get_max_cvss_score(), 9.5)