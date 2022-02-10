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
from typing import Any
from unittest import TestCase

from ossindex.serializer import json_decoder, OssIndexJsonEncoder
from . import FIXTURES_DIRECTORY
from .data import component_pip_18_no_vulnerabilities, component_pip_18_with_multiple_vulnerabilities


class TestSerializer(TestCase):

    def test_encode_simple_component(self) -> None:
        self._assert_serialisation_correct(
            o=[component_pip_18_no_vulnerabilities()], fixture_filename='component_pip_18_no_vulnerabilities.json'
        )

    def test_encode_component_with_vulnerabilities(self) -> None:
        self._assert_serialisation_correct(
            o=[component_pip_18_with_multiple_vulnerabilities()],
            fixture_filename='component_pip_18_with_multiple_vulnerabilities.json'
        )

    def test_decode_simple_component(self) -> None:
        with open(os.path.join(FIXTURES_DIRECTORY, 'component_pip_18_no_vulnerabilities.json'), mode='r',
                  encoding='utf-8') as expected:
            self.assertEqual(
                component_pip_18_no_vulnerabilities(),
                json.loads(expected.read(), object_hook=json_decoder).pop()
            )

    def test_decode_component_with_vulnerabilities(self) -> None:
        with open(os.path.join(FIXTURES_DIRECTORY, 'component_pip_18_with_multiple_vulnerabilities.json'), mode='r',
                  encoding='utf-8') as expected:
            self.assertEqual(
                component_pip_18_with_multiple_vulnerabilities(),
                json.loads(expected.read(), object_hook=json_decoder).pop()
            )

    def _assert_serialisation_correct(self, o: object, fixture_filename: str) -> None:
        with open(os.path.join(FIXTURES_DIRECTORY, fixture_filename), mode='r', encoding='utf-8') as expected:
            self.assertEqual(
                TestSerializer._sort_json_dict(json.loads(expected.read())),
                TestSerializer._sort_json_dict(json.loads(json.dumps(o, cls=OssIndexJsonEncoder)))
            )

    @staticmethod
    def _sort_json_dict(item: object) -> Any:
        if isinstance(item, dict):
            return sorted((key, TestSerializer._sort_json_dict(values)) for key, values in item.items())
        if isinstance(item, list):
            return sorted(TestSerializer._sort_json_dict(x) for x in item)
        else:
            return item
