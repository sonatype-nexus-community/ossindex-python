from unittest import TestCase, mock
from unittest.mock import MagicMock

from packageurl import PackageURL
from typing import List

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
        self.assertEqual(len(results), 1)

        first_result: OssIndexComponent = results[0]
        self.assertFalse(first_result.has_known_vulnerabilities())
        self.assertEqual(len(first_result.get_vulnerabilities()), 0)

    @mock.patch('requests.post', side_effect=mock_oss_index_post)
    def test_oss_index_with_vulnerabilities(self, mock_post: MagicMock):
        oss: OssIndex = OssIndex(enable_cache=False)

        results: List[OssIndexComponent] = oss.get_component_report(packages=[
            PackageURL(type='pypi', name='cryptography', version='3.3.1')
        ])

        mock_post.assert_called()
        self.assertEqual(len(results), 1)

        first_result: OssIndexComponent = results[0]
        self.assertTrue(first_result.has_known_vulnerabilities())
        self.assertEqual(len(first_result.get_vulnerabilities()), 1)

        first_vulnerability: Vulnerability = first_result.get_vulnerabilities()[0]
        self.assertIsInstance(first_vulnerability.get_id(), str)
        self.assertEqual(first_vulnerability.get_id(), '333aca51-7375-4a9d-be64-16d316ab9274')
        self.assertIsInstance(first_vulnerability.get_display_name(), str)
        self.assertEqual(first_vulnerability.get_display_name(), 'CVE-2020-36242')
        self.assertIsInstance(first_vulnerability.get_title(), str)
        self.assertGreater(len(first_vulnerability.get_title()), 0)
        self.assertIsInstance(first_vulnerability.get_description(), str)
        self.assertGreater(len(first_vulnerability.get_description()), 0)
        self.assertIsInstance(first_vulnerability.get_cvss_score(), float)
        self.assertEqual(first_vulnerability.get_cvss_score(), 9.1)
        self.assertIsInstance(first_vulnerability.get_cvss_vector(), str)
        self.assertEqual(first_vulnerability.get_cvss_vector(), 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H')
        self.assertIsNone(first_vulnerability.get_cwe())
        self.assertIsInstance(first_vulnerability.get_cve(), str)
        self.assertEqual(first_vulnerability.get_cve(), 'CVE-2020-36242')
        self.assertIsInstance(first_vulnerability.get_oss_index_reference_url(), str)
        self.assertIsNotNone(first_vulnerability.get_oss_index_reference_url())
        self.assertIsInstance(first_vulnerability.get_external_reference_urls(), list)
        self.assertEqual(len(first_vulnerability.get_external_reference_urls()), 1)
        self.assertEqual(
            first_vulnerability.get_external_reference_urls()[0],
            'https://nvd.nist.gov/vuln/detail/CVE-2020-36242'
        )

    @mock.patch('requests.post', side_effect=mock_oss_index_post)
    def test_oss_index_with_multiple_packages(self, mock_post: MagicMock):
        oss: OssIndex = OssIndex(enable_cache=False)

        results: List[OssIndexComponent] = oss.get_component_report(packages=[
            PackageURL(type='pypi', name='cryptography', version='3.3.1'),
            PackageURL(type='pypi', name='pip', version='21.2.3')
        ])

        mock_post.assert_called()
        self.assertEqual(len(results), 2)
