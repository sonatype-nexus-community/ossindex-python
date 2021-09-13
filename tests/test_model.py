import json
import os
from unittest import TestCase

from ossindex.model import OssIndexComponent

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
