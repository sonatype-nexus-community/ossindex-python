<!--

    Copyright 2022-Present Sonatype Inc.

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

-->

# Python Library for quering OSS Index

![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/sonatype-nexus-community/ossindex-python/ci.yml?branch=main)
![Python Version Support](https://img.shields.io/badge/python-3.6+-blue)
![PyPI Version](https://img.shields.io/pypi/v/ossindex-lib?label=PyPI&logo=pypi)
[![Documentation](https://readthedocs.org/projects/ossindex-library/badge/?version=latest)](https://readthedocs.org/projects/ossindex-library)
[![GitHub license](https://img.shields.io/github/license/sonatype-nexus-community/ossindex-python)](https://github.com/sonatype-nexus-community/ossindex-python/blob/main/LICENSE)
[![GitHub issues](https://img.shields.io/github/issues/sonatype-nexus-community/ossindex-python)](https://github.com/sonatype-nexus-community/ossindex-python/issues)
[![GitHub forks](https://img.shields.io/github/forks/sonatype-nexus-community/ossindex-python)](https://github.com/sonatype-nexus-community/ossindex-python/network)
[![GitHub stars](https://img.shields.io/github/stars/sonatype-nexus-community/ossindex-python)](https://github.com/sonatype-nexus-community/ossindex-python/stargazers)

----

This OSSIndex module for Python provides a common interface to querying the [OSS Index](https://ossindex.sonatype.org/).

This module is not designed for standalone use. If you're looking for a tool that can detect your application's dependencies
and assess them for vulnerabilities against the OSS Index, perhaps you should check out 
[Jake](https://github.com/sonatype-nexus-community/jake).

You can of course use this library in your own applications.

## Installation

Install from pypi.org as you would any other Python module:

```
pip install ossindex-lib
```

## Usage

First create an instance of `OssIndex`, optionally enabling local caching
```
o = OssIndex()
```

Then supply a `List` of [PackageURL](https://github.com/package-url/packageurl-python) objects that you want to ask
OSS Index about. If you don't want to care about generating this list yourself, perhaps look to a tool like [Jake](https://github.com/sonatype-nexus-community/jake)
(which uses this library) and will do all the hard work for you!

As a quick test, you could run:
```
o = OssIndex()
results: List[OssIndexComponent] = o.get_component_report(packages=[
    PackageURL.from_string(purl='pkg:pypi/pip@19.2.0')
])
for r in results:
    print("{}: {} known vulnerabilities".format(r.get_coordinates(), len(r.get_vulnerabilities())))
    v: Vulnerability
    for v in r.get_vulnerabilities():
        print('    - {}'.format(str(v)))
```

... which would output something like ...
```
pkg:pypi/pip@19.2.0: 1 known vulnerabilities
    - <Vulnerability id=e4c955a3-2004-472e-920b-783fea46c3cd, name=OSSINDEX-783f-ea46-c3cd, cvss_score=3.6>
```

## Logging

This library send log events to a standard Python `logger` named `ossindex`. You can configure the logger to output as
required through the standard [Python logging configuration](https://docs.python.org/3/library/logging.config.html).

## Todos

1. Support authentication against OSS Index

## Python Support

We endeavour to support all functionality for all [current actively supported Python versions](https://www.python.org/downloads/).
However, some features may not be possible/present in older Python versions due to their lack of support.

## Changelog

See our [CHANGELOG](./CHANGELOG.md).

## The Fine Print

Remember:

It is worth noting that this is **NOT SUPPORTED** by Sonatype, and is a contribution of ours to the open source
community (read: you!)

* Use this contribution at the risk tolerance that you have
* Do NOT file Sonatype support tickets related to `ossindex-lib`
* DO file issues here on GitHub, so that the community can pitch in

Phew, that was easier than I thought. Last but not least of all - have fun!
