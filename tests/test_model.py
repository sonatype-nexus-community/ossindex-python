#
# Copyright 2022-Present Sonatype Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import json
import os
from typing import List
from unittest import TestCase
from uuid import uuid4

from ossindex.model import OssIndexComponent, Vulnerability
from ossindex.serializer import json_decoder
from tests import FIXTURES_DIRECTORY


class TestModel(TestCase):

    def test_response_parse_no_vulnerabilities(self):
        with open(os.path.join(FIXTURES_DIRECTORY, 'oss-index-response-no-vulnerabilities.json'),
                  'r') as expected_response:
            json_response = json.loads(expected_response.read())

            self.assertEqual(1, len(json_response), 'More than one component parsed!')

            oic = OssIndexComponent(**json_response[0])
            self.assertIsInstance(oic, OssIndexComponent)
            self.assertEqual('pkg:pypi/pip@21.2.4', oic.coordinates)
            self.assertEqual('The PyPA recommended tool for installing Python packages.', oic.description)
            self.assertEqual(
                'https://ossindex.sonatype.org/component/pkg:pypi/pip@21.2.4?utm_source=mozilla&utm_medium=integration'
                '&utm_content=5.0', oic.reference
            )
            self.assertEqual(0, len(oic.vulnerabilities))

    def test_response_one_vulnerability(self):
        with open(os.path.join(FIXTURES_DIRECTORY, 'oss-index-response-1-vulnerability.json'),
                  'r') as expected_response:
            oics: List[OssIndexComponent] = json.loads(expected_response.read(), object_hook=json_decoder)

            self.assertEqual(1, len(oics), 'More than one component parsed!')
            oic = oics[0]
            self.assertIsInstance(oic, OssIndexComponent)
            self.assertEqual('pkg:pypi/pip@19.2.0', oic.coordinates)
            self.assertEqual('The PyPA recommended tool for installing Python packages.', oic.description)
            self.assertEqual(
                'https://ossindex.sonatype.org/component/pkg:pypi/pip@19.2.0?utm_source=mozilla&utm_medium=integration'
                '&utm_content=5.0', oic.reference
            )
            self.assertEqual(1, len(oic.vulnerabilities))
            v1 = oic.vulnerabilities.pop()
            self.assertEqual('e4c955a3-2004-472e-920b-783fea46c3cd', v1.id)
            self.assertEqual('OSSINDEX-783f-ea46-c3cd', v1.display_name)
            self.assertEqual('CWE-22: Improper Limitation of a Pathname to a Restricted Directory (\'Path Traversal\')',
                             v1.title)
            self.assertEqual(
                'The software uses external input to construct a pathname that is intended to identify a file or '
                'directory that is located underneath a restricted parent directory, but the software does not '
                'properly neutralize special elements within the pathname that can cause the pathname to resolve to a '
                'location that is outside of the restricted directory.', v1.description)
            self.assertEqual(3.6, v1.cvss_score)
            self.assertEqual('CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N', v1.cvss_vector)
            self.assertEqual('CWE-22', v1.cwe)
            self.assertEqual('https://ossindex.sonatype.org/vulnerability/e4c955a3-2004-472e-920b-783fea46c3cd'
                             '?component-type=pypi&component-name=pip&utm_source=mozilla&utm_medium=integration'
                             '&utm_content=5.0', v1.reference)
            self.assertEqual(1, len(v1.external_references))

    def test_max_cvss_score_1(self):
        vulns = [
            Vulnerability(
                id_=str(uuid4()), display_name='Test Vuln 1', title='Test Vuln 1', description='', cvss_score=9.0,
                reference='Some reference'
            ),
            Vulnerability(
                id_=str(uuid4()), display_name='Test Vuln 2', title='Test Vuln 2', description='', cvss_score=5.0,
                reference='Some reference'
            )
        ]
        oic = OssIndexComponent(
            coordinates='test@1.0.0', description='Test', reference='https://test.com',
            vulnerabilities=vulns
        )
        self.assertEqual(2, len(oic.vulnerabilities))
        self.assertEqual(9.0, oic.get_max_cvss_score())

    def test_max_cvss_score_2(self):
        vulns = [
            Vulnerability(
                id_=str(uuid4()), display_name='Test Vuln 2', title='Test Vuln 2', description='', cvss_score=5.0,
                reference='Some reference'
            ),
            Vulnerability(
                id_=str(uuid4()), display_name='Test Vuln 1', title='Test Vuln 1', description='', cvss_score=9.5,
                reference='Some reference'
            ),
            Vulnerability(
                id_=str(uuid4()), display_name='Test Vuln 3', title='Test Vuln 3', description='', cvss_score=1.5,
                reference='Some reference'
            )
        ]
        oic = OssIndexComponent(
            coordinates='test@1.0.0', description='Test', reference='https://test.com',
            vulnerabilities=vulns
        )
        self.assertEqual(3, len(oic.vulnerabilities))
        self.assertEqual(9.5, oic.get_max_cvss_score())
