# Python Library for quering OSS Index

![GitHub Workflow Status](https://img.shields.io/github/workflow/status/sonatype-nexus-community/ossindex-python/Python%20CI)
![Python Version Support](https://img.shields.io/badge/python-3.6+-blue)
![PyPI Version](https://img.shields.io/pypi/v/ossindex-lib?label=PyPI&logo=pypi)
[![GitHub license](https://img.shields.io/github/license/sonatype-nexus-community/ossindex-python)](https://github.com/sonatype-nexus-community/ossindex-python/blob/main/LICENSE)
[![GitHub issues](https://img.shields.io/github/issues/sonatype-nexus-community/ossindex-python)](https://github.com/sonatype-nexus-community/ossindex-python/issues)
[![GitHub forks](https://img.shields.io/github/forks/sonatype-nexus-community/ossindex-python)](https://github.com/sonatype-nexus-community/ossindex-python/network)
[![GitHub stars](https://img.shields.io/github/stars/sonatype-nexus-community/ossindex-pythonb)](https://github.com/sonatype-nexus-community/ossindex-python/stargazers)

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
