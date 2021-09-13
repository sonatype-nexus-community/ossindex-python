import os
from pathlib import Path
from tinydb import TinyDB
from typing import List

DEFAULT_HEADERS = {
    'Content-type': 'application/vnd.ossindex.component-report-request.v1+json',
    'User-Agent': 'pypi-ossindex-lib'}


class OssIndex:
    _caching_enabled: bool = False
    _cache_database: TinyDB = None
    _cache_directory: str = '.ossindex'
    _cache_location: Path = None

    _oss_index_host: str = 'https://ossindex.sonatype.org'
    _oss_max_coordinates_per_request: int = 128

    def __init__(self, enable_cache: bool = False, cache_location: str = None):
        self._caching_enabled = enable_cache
        if self._caching_enabled:
            self._setup_cache(cache_location=cache_location)

    def get_component_report(self, List):

    def _setup_cache(self, cache_location: str = None):
        full_cache_path: str
        if not cache_location:
            full_cache_path = os.path.join(Path.home(), self._cache_directory)
        else:
            full_cache_path = os.path.join(cache_location, self._cache_directory)

        if not os.path.exists(full_cache_path):
            Path(full_cache_path).mkdir(parents=True, exist_ok=True)

        self._cache_directory = Path(full_cache_path)
        self._cache_database = TinyDB(os.path.join(self._cache_directory, 'ossindex.json'))



    def get_url(self):
        """gets url to use for OSSIndex request"""
        return self._url

    def get_headers(self):
        """gets headers to use for OSSIndex request"""
        return self._headers

    def chunk(self, coords: Coordinates):
        """chunks up purls array into 128-purl subarrays"""
        chunks = []
        divided = []
        length = len(coords.get_coordinates())
        num_chunks = length // self._maxcoords
        if length % self._maxcoords > 0:
            num_chunks += 1
        start_index = 0
        end_index = self._maxcoords
        for i in range(0, num_chunks):
            if i == (num_chunks - 1):
                divided = coords.get_purls()[start_index:length]
            else:
                divided = coords.get_purls()[start_index:end_index]
                start_index = end_index
                end_index += end_index
            chunks.append(divided)
        return chunks

    def call_ossindex(self, coords: Coordinates) -> (list):
        """makes a request to OSSIndex"""
        self._log.debug("Purls received, total purls before chunk: %s",
                        len(coords.get_coordinates()))

        (coords, results) = self.get_purls_and_results_from_cache(coords)

        self._log.debug("Purls checked against cache, total purls remaining to "
                        "call OSS Index: %s",
                        len(coords.get_coordinates()))

        chunk_purls = self.chunk(coords)
        for purls_chunk in chunk_purls:
            data = {}
            data["coordinates"] = purls_chunk
            config_file = Config()
            if config_file.check_if_config_exists() is False:
                response = requests.post(self.get_url(), data=json.dumps(
                    data), headers=self.get_headers())
            else:
                auth = config_file.get_config_from_file(
                    ".oss-index-config")

                response = requests.post(self.get_url(),
                                         data=json.dumps(data),
                                         headers=self.get_headers(),
                                         auth=(auth["Username"], auth["Token"]))
            if response.status_code == 200:
                self._log.debug(response.headers)
                first_results = json.loads(response.text, cls=ResultsDecoder)
            else:
                self._log.debug("Response failed, status: %s",
                                response.status_code)
                self._log.debug("Failure reason if any: %s", response.reason)
                self._log.debug("Failure text if any: %s", response.text)
                return None
            results.extend(first_results)

        (cached, num_cached) = self.maybe_insert_into_cache(results)
        self._log.debug("Cached: <%s> num_cached: <%s>", cached, num_cached)
        return results

    def maybe_insert_into_cache(self, results: List[CoordinateResults]):
        """checks to see if result is in cache and if not, stores it"""
        coordinate_query = Query()
        num_cached = 0
        cached = False
        for coordinate in results:
            mydatetime = datetime.now()
            twelvelater = mydatetime + timedelta(hours=12)
            result = self._db.search(
                coordinate_query.purl == coordinate.get_coordinates())
            if len(result) == 0:
                self._db.insert({'purl': coordinate.get_coordinates(),
                                 'response': coordinate.to_json(),
                                 'ttl': twelvelater.isoformat()})
                self._log.debug(
                    "Coordinate inserted into cache: <%s>",
                    coordinate.get_coordinates())
                num_cached += 1
                cached = True
            else:
                timetolive = DT.datetime.strptime(
                    result[0]['ttl'],
                    '%Y-%m-%dT%H:%M:%S.%f'
                )
                if mydatetime > timetolive:
                    self._db.update({'response': coordinate.to_json(),
                                     'ttl': twelvelater.isoformat()},
                                    doc_ids=[result[0].doc_id])
                    self._log.debug(
                        "Coordinate: <%s> updated in cache because TTL"
                        " expired",
                        coordinate.get_coordinates())
                    num_cached += 1
                    cached = True

        return (cached, num_cached)

    def get_purls_and_results_from_cache(self, purls: Coordinates) -> (Coordinates, list):
        """get cached purls and results from cache"""
        valid = isinstance(purls, Coordinates)
        if not valid:
            return (None, None)
        new_purls = Coordinates()
        results = []
        coordinate_query = Query()
        for coordinate, purl in purls.get_coordinates().items():
            mydatetime = datetime.now()
            result = self._db.search(coordinate_query.purl == purl)
            if len(result) == 0 or DT.datetime.strptime(
                    result[0]['ttl'],
                    '%Y-%m-%dT%H:%M:%S.%f'
            ) < mydatetime:
                new_purls.add_coordinate(coordinate[0], coordinate[1], coordinate[2])
            else:
                results.append(json.loads(
                    result[0]['response'], cls=ResultsDecoder))
        return (new_purls, results)

    def clean_cache(self):
        """removes all documents from the table"""
        self._db.truncate()
        return True

    def close_db(self):
        """closes connection to TinyDB"""
        self._db.close()
