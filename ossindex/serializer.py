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
import re
from typing import Any, Dict

from .model import OssIndexComponent, Vulnerability


def pythonify_key_names(d: Dict[str, Any]) -> Dict[Any, Any]:
    named_d: Dict[Any, Any] = {}
    # Covert Key Names
    for (k, v) in d.items():
        new_k = re.sub(r'(?<!^)(?=[A-Z])', '_', k).lower()

        if k == 'id':
            # Special case for reserved keyword
            new_k = 'id_'

        named_d[new_k] = v
    return named_d


def json_decoder(o: object) -> object:
    if isinstance(o, dict):
        named_o = pythonify_key_names(d=o)
        if 'vulnerabilities' in named_o.keys():
            return OssIndexComponent(**named_o)
        elif 'id_' in named_o.keys():
            return Vulnerability(**named_o)

    raise ValueError(
        f'Unknown value in JSON being decoded: {o}'
    )
