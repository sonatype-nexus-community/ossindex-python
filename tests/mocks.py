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
#
import json
from typing import Callable, Optional


class MockResponse:
    def __init__(self, data: Optional[str], status_code: int) -> None:
        self._text = data if data else ''
        self._status_code = status_code

    @property
    def status_code(self) -> int:
        return self._status_code

    @property
    def text(self) -> str:
        return self._text

    def json(self, object_hook: Callable) -> object:
        return json.loads(self.text, object_hook=object_hook)


def mock_oss_index_post(*args, **kwargs) -> MockResponse:
    if 'url' in kwargs.keys() and kwargs['url'] == 'https://ossindex.sonatype.org/api/v3/component-report':
        request_json = kwargs['json'] if 'json' in kwargs.keys() else {}

        if 'coordinates' in request_json.keys() and len(request_json['coordinates']) > 0:
            mock_response_data = []
            if 'pkg:pypi/pip@0.0.7' in request_json['coordinates']:
                return MockResponse(None, 401)

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
