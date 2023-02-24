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

from ossindex.model import OssIndexComponent, Vulnerability


def component_pip_18_no_vulnerabilities() -> OssIndexComponent:
    return OssIndexComponent(
        coordinates='pkg:pypi/pip@18.1',
        description='The PyPA recommended tool for installing Python packages.',
        reference='https://ossindex.sonatype.org/component/pkg:pypi/pip@18.1?utm_source=mozilla&utm_medium=integration'
                  '&utm_content=5.0'
    )


def component_pip_18_with_multiple_vulnerabilities() -> OssIndexComponent:
    oic = component_pip_18_no_vulnerabilities()
    oic.vulnerabilities.add(
        Vulnerability(
            id_='6dcf0940-d3c7-480f-84de-e90c3631ea81',
            display_name='CVE-2019-20916',
            title='[CVE-2019-20916] The pip package before 19.2 for Python allows Directory Traversal when a URL is '
                  '...',
            description='The pip package before 19.2 for Python allows Directory Traversal when a URL is given in an '
                        'install command, because a Content-Disposition header can have ../ in a filename, as '
                        'demonstrated by overwriting the /root/.ssh/authorized_keys file. This occurs in '
                        '_download_http_url in _internal/download.py.',
            cvss_score=7.5,
            cvss_vector='CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N',
            cve='CVE-2019-20916',
            reference='https://ossindex.sonatype.org/vulnerability/6dcf0940-d3c7-480f-84de-e90c3631ea81?'
                      'component-type=pypi&component-name=pip&utm_source=mozilla&utm_medium=integration'
                      '&utm_content=5.0',
            external_references=[
                'https://nvd.nist.gov/vuln/detail/CVE-2019-20916'
            ]
        ),
    )
    oic.vulnerabilities.add(
        Vulnerability(
            id_='e4c955a3-2004-472e-920b-783fea46c3cd',
            display_name='OSSINDEX-783f-ea46-c3cd',
            title='CWE-22: Improper Limitation of a Pathname to a Restricted Directory (\'Path Traversal\')',
            description='The software uses external input to construct a pathname that is intended to identify a file '
                        'or directory that is located underneath a restricted parent directory, but the software does '
                        'not properly neutralize special elements within the pathname that can cause the pathname to '
                        'resolve to a location that is outside of the restricted directory.',
            cvss_score=3.6,
            cvss_vector='CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N',
            cwe='CWE-22',
            reference='https://ossindex.sonatype.org/vulnerability/e4c955a3-2004-472e-920b-783fea46c3cd?'
                      'component-type=pypi&component-name=pip&utm_source=mozilla&utm_medium=integration'
                      '&utm_content=5.0',
            external_references=[
                'https://github.com/pypa/pip/issues/730'
            ]
        )
    )
    return oic
