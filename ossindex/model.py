from typing import List
from urllib.parse import ParseResult, urlparse
from uuid import UUID

from packageurl import PackageURL


class Vulnerability:
    _id: UUID
    _display_name: str
    _title: str
    _description: str
    _cvss_score: float
    _cvss_vector: str
    _cwe: str
    _oss_index_url: ParseResult
    _external_references: List[ParseResult]

    @staticmethod
    def from_json(o: dict):
        """
        This method attempts to parse a response from OSS Index to a Vulnerability

        Example payload:
          {
            "id": "e4c955a3-2004-472e-920b-783fea46c3cd",
            "displayName": "OSSINDEX-783f-ea46-c3cd",
            "title": "CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
            "description": "The software uses external input to construct a pathname that is intended to ...",
            "cvssScore": 3.6,
            "cvssVector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N",
            "cwe": "CWE-22",
            "reference": "https://ossindex.sonatype.org/vulnerability/e4c955a3-2004-472e-920b-783fea46c3cd \
                ?component-type=pypi&component-name=pip&utm_source=mozilla&utm_medium=integration&utm_content=5.0",
            "externalReferences": [
              "https://github.com/pypa/pip/issues/730"
            ]
          }

        :param o: dict
        :return: Vulnerability
        """

        v = Vulnerability(
            id=o['id'],
            display_name=o['displayName'],
            title=o['title'],
            description=o['description'],
            cvss_score=o['cvssScore'],
            cvss_vector=o['cvssVector'],
            cwe=o['cwe'],
            oss_index_url=o['reference'],
            external_references=o['externalReferences']
        )

        return v

    def __init__(self, id: str, display_name: str, title: str, description: str = None,
                 cvss_score: float = None, cvss_vector: str = None, cwe: str = None,
                 oss_index_url: str = None, external_references: List[str] = []):
        self._id = id
        self._display_name = display_name
        self._title = title
        self._description = description
        self._cvss_score = cvss_score
        self._cvss_vector = cvss_vector
        self._cwe = cwe
        if oss_index_url:
            self._oss_index_url = urlparse(oss_index_url)
        self._external_references = []
        for ext_ref in external_references:
            self._external_references.append(urlparse(ext_ref))

    def __repr__(self):
        return '<Vulnerability id={}, name={}, cvss_score={}>'.format(
            self._id, self._display_name, self._cvss_score
        )

    def to_json(self):
        return {
            'id': self._id,
            'displayName': self._display_name,
            'title': self._title,
            'description': self._description,
            'cvssScore': self._cvss_score,
            'cvssVector': self._cvss_vector,
            'cwe': self._cwe,
            'reference': None if self._oss_index_url is None else str(self._oss_index_url),
            'externalReferences': list(map(lambda ref: ref.geturl(), self._external_references))
        }


class OssIndexComponent:
    _coordinates: str
    _description: str
    _oss_index_url: ParseResult
    _vulnerabilities: List[Vulnerability] = []

    @staticmethod
    def from_json(o: dict):
        oic = OssIndexComponent(
            coordinates=o['coordinates'],
            description=o['description'] if 'description' in o.keys() else None,
            oss_index_reference_url=o['reference'],
            vulnerabilities=o['vulnerabilities']
        )

        return oic

    def __init__(self, coordinates: str, description: str, oss_index_reference_url: str,
                 vulnerabilities: List[Vulnerability] = []):
        self._coordinates = coordinates
        self._description = description
        self._oss_index_url = urlparse(oss_index_reference_url, allow_fragments=False)
        self._vulnerabilities = vulnerabilities

    def __repr__(self) -> str:
        return '<OssIndexComponent coordinates={}, vulnerabilites={}>'.format(
            self._coordinates, len(self._vulnerabilities)
        )

    def get_coordinates(self) -> str:
        return self._coordinates

    def get_description(self) -> str:
        return self._description

    def get_package_url(self) -> PackageURL:
        return PackageURL.from_string(purl=self.get_coordinates())

    def get_reference_url(self) -> str:
        return str(self._oss_index_url)

    def get_vulnerabilities(self) -> List[Vulnerability]:
        return self._vulnerabilities

    def has_known_vulnerabilities(self) -> bool:
        return len(self._vulnerabilities) != 0

    def _add_vulnerability(self, vulnerability: Vulnerability):
        self._vulnerabilities.append(vulnerability)

    def set_vulnerabilities(self, vulnerabilities: List[Vulnerability]):
        self._vulnerabilities = vulnerabilities

    def to_json(self):
        return {
            'coordinates': self.get_coordinates(),
            'description': self.get_description(),
            'reference': self.get_reference_url(),
            'vulnerabilities': list(map(lambda v: v.to_json(), self.get_vulnerabilities()))
        }
