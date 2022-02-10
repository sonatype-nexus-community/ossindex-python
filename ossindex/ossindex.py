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
import logging
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional

import pkg_resources
import requests
# See https://github.com/package-url/packageurl-python/issues/65
from packageurl import PackageURL  # type: ignore
from tinydb import TinyDB, Query
from tinydb.table import Document

from .model import OssIndexComponent
from .serializer import json_decoder

logger = logging.getLogger('ossindex')


class OssIndex:
    _caching_enabled: bool = False
    _cache_database: Optional[TinyDB] = None
    _cache_directory: str = '.ossindex'
    _cache_ttl_in_hours: int = 12

    _oss_index_api_version: str = 'v3'
    _oss_index_host: str = 'https://ossindex.sonatype.org'
    _oss_max_coordinates_per_request: int = 128

    def __init__(self, *, enable_cache: bool = True, cache_location: Optional[str] = None) -> None:
        self._caching_enabled = enable_cache
        if self._caching_enabled:
            logger.info('OssIndex caching is ENABLED')
            self._setup_cache(cache_location=cache_location)

    def __del__(self) -> None:
        if self._caching_enabled and self._cache_database:
            logger.debug('Closing cache DB safely')
            self._cache_database.close()

    def get_component_report(self, packages: List[PackageURL]) -> List[OssIndexComponent]:
        logger.debug('A total of {} Packages to be queried against OSS Index'.format(len(packages)))
        return self._get_results(packages=packages)

    def purge_local_cache(self) -> None:
        if self._caching_enabled and self._cache_database:
            logger.info('Truncating local cache database as requested')
            self._cache_database.truncate()
            logger.info('Local OSS Index cache has been purged')

    def _chunk_packages_for_oss_index(self, packages: List[PackageURL]) -> List[List[PackageURL]]:
        """
        Splits up the list of packages into lists that are of a size consumable by OSS Index
        APIs.

        :param packages: List[PackageURL]
        :return: List[List[PackageURL]]
        """
        return list(
            [packages[i: i + self._oss_max_coordinates_per_request] for i in
             range(0, len(packages), self._oss_max_coordinates_per_request)]
        )

    def _get_api_url(self, api_uri: str) -> str:
        return '{}/api/{}/{}'.format(
            self._oss_index_host, self._oss_index_api_version, api_uri
        )

    def _get_cached_results(self, packages: List[PackageURL]) -> tuple[List[PackageURL], List[OssIndexComponent]]:
        """
        Takes a list of packages and returns two Lists:
            1. Packages without cached results
            2. Cached results for those packages where they exist

        :param packages: List[PackageURL]
        :return: (List[PackageURL], List[OssIndexComponent])
        """
        if not self._caching_enabled or not self._cache_database:
            # This should not be possible, but adding for developer safety
            return packages, []

        now = datetime.now()
        cached_results: List[OssIndexComponent] = []
        non_cached_packaged: List[PackageURL] = []
        for package in packages:
            logger.debug('   Checking in cache for {}'.format(package.to_string()))
            cache_results: List[Document] = self._cache_database.search(Query().coordinates == package.to_string())
            if len(cache_results) == 0:
                # Not cached
                logger.debug('      Not in cache')
                non_cached_packaged.append(package)
            elif datetime.strptime(cache_results[0]['expiry'], '%Y-%m-%dT%H:%M:%S.%f') < now:
                logger.debug('      Cached, but result expired')
                non_cached_packaged.append(package)
            else:
                logger.debug('      Cached, loading from cache')
                cached_results.append(
                    json.loads(json.dumps(cache_results[0]['response']), object_hook=json_decoder)
                )

        return non_cached_packaged, cached_results

    @staticmethod
    def _get_headers() -> dict[str, str]:
        return {
            'Accept': 'application/vnd.ossindex.component-report.v1+json',
            'Content-type': 'application/vnd.ossindex.component-report-request.v1+json',
            'User-Agent': 'python-oss-index-lib@{}'.format(
                pkg_resources.get_distribution('ossindex-lib').version
            )
        }

    def _get_results(self, packages: List[PackageURL]) -> List[OssIndexComponent]:
        results: List[OssIndexComponent] = list()

        # First get any cached results
        if self._caching_enabled:
            logger.debug('Checking local cache for any usable results...')
            packages, results = self._get_cached_results(packages=packages)
            logger.debug('   {} cached results found leaving {} to ask OSS Index'.format(
                len(results), len(packages)
            ))

        # Second, chunk up packages for which we have no cached results and query OSS Index
        chunk: List[PackageURL]
        chunks = self._chunk_packages_for_oss_index(packages=packages)
        logger.debug('Split {} packages into {} chunks for OSS requests'.format(len(packages), len(chunks)))
        for chunk in chunks:
            logger.debug('  Getting chunk results from OSS Index...')
            results = results + self._make_oss_index_component_report_call(packages=chunk)

        logger.debug('Total of {} results (including cached)'.format(len(results)))
        return results

    def _make_oss_index_component_report_call(self, packages: List[PackageURL]) -> List[OssIndexComponent]:
        response = requests.post(
            url=self._get_api_url('component-report'),
            headers=self._get_headers(),
            json={
                'coordinates': list(map(lambda p: str(p.to_string()), packages))
            }
        )
        results: List[OssIndexComponent] = []
        for oic in response.json(object_hook=json_decoder):
            results.append(oic)

        if self._caching_enabled:
            self._upsert_cache_with_oss_index_responses(oss_components=results)
        return results

    def _upsert_cache_with_oss_index_responses(self, oss_components: List[OssIndexComponent]) -> None:
        if not self._caching_enabled or not self._cache_database:
            return

        now = datetime.now()
        cache_expiry = now + timedelta(hours=self._cache_ttl_in_hours)
        oc: OssIndexComponent
        for oc in oss_components:
            cache_query_result: List[Document] = self._cache_database.search(
                Query().coordinates == oc.coordinates)
            if len(cache_query_result) == 0:
                # New component for caching
                logger.debug('    Caching new Component results for {}'.format(oc.coordinates))
                self._cache_database.insert({
                    'coordinates': oc.coordinates,
                    'response': json.dumps(oc),
                    'expiry': cache_expiry.isoformat()
                })
            else:
                # Update existing cache
                logger.debug('    Might refresh cache for {}'.format(oc.coordinates))
                if now > datetime.strptime(cache_query_result[0]['expiry'], '%Y-%m-%dT%H:%M:%S.%f'):
                    # Cache expired - update it!
                    logger.debug('        Cache expired for {} - UPDATING CACHE'.format(oc.coordinates))
                    self._cache_database.update({
                        'response': json.dumps(oc),
                        'expiry': cache_expiry.isoformat()
                    }, cache_query_result[0].doc_id)
                else:
                    logger.debug('    Cache is still valid for {} - not updating'.format(oc.coordinates))

    def _setup_cache(self, cache_location: Optional[str] = None) -> None:
        full_cache_path: str
        if not cache_location:
            full_cache_path = os.path.join(Path.home(), self._cache_directory)
        else:
            full_cache_path = os.path.join(cache_location, self._cache_directory)

        if not os.path.exists(full_cache_path):
            Path(full_cache_path).mkdir(parents=True, exist_ok=True)

        self._cache_directory = str(Path(full_cache_path))
        self._cache_database = TinyDB(os.path.join(self._cache_directory, 'ossindex.json'))
