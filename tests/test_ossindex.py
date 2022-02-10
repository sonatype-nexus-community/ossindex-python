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
from typing import List
from unittest import TestCase, mock
from unittest.mock import MagicMock

from packageurl import PackageURL

from mocks import mock_oss_index_post
from ossindex.model import OssIndexComponent, Vulnerability
from ossindex.ossindex import OssIndex


class TestOssIndex(TestCase):

    @mock.patch('requests.post', side_effect=mock_oss_index_post)
    def test_oss_index_no_vulnerabilities(self, mock_post: MagicMock):
        oss: OssIndex = OssIndex(enable_cache=False)

        results: List[OssIndexComponent] = oss.get_component_report(packages=[
            PackageURL(type='pypi', name='pip', version='21.2.3')
        ])

        mock_post.assert_called()
        self.assertEqual(1, len(results))

        print(f'{results}')

        first_result: OssIndexComponent = results.pop()
        self.assertEqual(0, len(first_result.vulnerabilities))

    @mock.patch('requests.post', side_effect=mock_oss_index_post)
    def test_oss_index_with_vulnerabilities(self, mock_post: MagicMock):
        oss: OssIndex = OssIndex(enable_cache=False)

        results: List[OssIndexComponent] = oss.get_component_report(packages=[
            PackageURL(type='pypi', name='cryptography', version='3.3.1')
        ])

        mock_post.assert_called()
        self.assertEqual(1, len(results))

        first_result: OssIndexComponent = results.pop()
        self.assertIsInstance(first_result, OssIndexComponent)
        self.assertTrue(first_result.vulnerabilities)
        self.assertEqual(1, len(first_result.vulnerabilities))

        first_vulnerability: Vulnerability = first_result.vulnerabilities.pop()
        self.assertEqual('333aca51-7375-4a9d-be64-16d316ab9274', first_vulnerability.id)
        self.assertEqual('CVE-2020-36242', first_vulnerability.display_name)
        self.assertEqual("[CVE-2020-36242] In the cryptography package before 3.3.2 for Python, certain "
                         "sequences of update...", first_vulnerability.title)
        self.assertEqual("In the cryptography package before 3.3.2 for Python, certain sequences of "
                         "update calls to symmetrically encrypt multi-GB values could result in an "
                         "integer overflow and buffer overflow, as demonstrated by the Fernet class.",
                         first_vulnerability.description)
        self.assertEqual(9.1, first_vulnerability.cvss_score)
        self.assertEqual('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H', first_vulnerability.cvss_vector)
        self.assertEqual('CVE-2020-36242', first_vulnerability.cve)
        self.assertEqual("https://ossindex.sonatype.org/vulnerability/333aca51-7375-4a9d-be64-"
                         "16d316ab9274?component-type=pypi&component-name=cryptography&"
                         "utm_source=mozilla&utm_medium=integration&utm_content=5.0", first_vulnerability.reference)
        self.assertEqual(1, len(first_vulnerability.external_references))
        self.assertEqual('https://nvd.nist.gov/vuln/detail/CVE-2020-36242',
                         first_vulnerability.external_references.pop())

    @mock.patch('requests.post', side_effect=mock_oss_index_post)
    def test_oss_index_with_multiple_packages(self, mock_post: MagicMock):
        oss: OssIndex = OssIndex(enable_cache=False)

        results: List[OssIndexComponent] = oss.get_component_report(packages=[
            PackageURL(type='pypi', name='cryptography', version='3.3.1'),
            PackageURL(type='pypi', name='pip', version='21.2.3')
        ])

        mock_post.assert_called()
        self.assertEqual(len(results), 2)
