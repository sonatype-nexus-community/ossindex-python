import json


def mock_oss_index_post(*args, **kwargs):
    class MockResponse:
        def __init__(self, data, status_code):
            self.text = data
            self._status_code = status_code

    if 'url' in kwargs.keys() and kwargs['url'] == 'https://ossindex.sonatype.org/api/v3/component-report':
        request_json = kwargs['json'] if 'json' in kwargs.keys() else {}

        if 'coordinates' in request_json.keys() and len(request_json['coordinates']) > 0:
            mock_response_data = []
            if 'pkg:pypi/pip@21.2.3' in request_json['coordinates']:
                mock_response_data.append({
                    "coordinates": "pkg:pypi/pip@21.2.3",
                    "description": "The PyPA recommended tool for installing Python packages.",
                    "reference": "https://ossindex.sonatype.org/component/pkg:pypi/pip@21.2.3?"
                                 "utm_source=mozilla&utm_medium=integration&utm_content=5.0",
                    "vulnerabilities": []
                })

            if 'pkg:pypi/cryptography@3.3.1' in request_json['coordinates']:
                mock_response_data.append({
                    "coordinates": "pkg:pypi/cryptography@3.3.1",
                    "description": "cryptography is a package which provides cryptographic recipes and primitives to "
                                   "Python developers.",
                    "reference": "https://ossindex.sonatype.org/component/pkg:pypi/cryptography@3.3.1?"
                                 "utm_source=mozilla&utm_medium=integration&utm_content=5.0",
                    "vulnerabilities": [
                        {
                            "id": "333aca51-7375-4a9d-be64-16d316ab9274",
                            "displayName": "CVE-2020-36242",
                            "title": "[CVE-2020-36242] In the cryptography package before 3.3.2 for Python, certain "
                                     "sequences of update...",
                            "description": "In the cryptography package before 3.3.2 for Python, certain sequences of "
                                           "update calls to symmetrically encrypt multi-GB values could result in an "
                                           "integer overflow and buffer overflow, as demonstrated by the Fernet class.",
                            "cvssScore": 9.1,
                            "cvssVector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H",
                            "cve": "CVE-2020-36242",
                            "reference": "https://ossindex.sonatype.org/vulnerability/333aca51-7375-4a9d-be64-"
                                         "16d316ab9274?component-type=pypi&component-name=cryptography&"
                                         "utm_source=mozilla&utm_medium=integration&utm_content=5.0",
                            "externalReferences": [
                                "https://nvd.nist.gov/vuln/detail/CVE-2020-36242"
                            ]
                        }
                    ]
                })

            return MockResponse(json.dumps(mock_response_data), 200)

        return MockResponse(None, 404)
