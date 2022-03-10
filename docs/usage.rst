.. # Copyright 2022-Present Sonatype Inc.
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

Usage
============

``ossindex-lib`` is designed to be included into other Python projects, not used as a standalone application.

Library Configuration
---------------------

There are two key configurations that are possible:

1. Caching of response from OSS Index
2. Authentication for OSS Index

Caching of OSS Index Responses
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

By default, caching is enabled and the cache will be stored in ``$HOME/.ossindex/``.

You can disable caching as follows:

.. code-block::

  ossi = OssIndex(enable_cache=False)

You can control the base directory where the cache directory ``.ossindex`` is created by supplying a directory as follows:

.. code-block::

  ossi = OssIndex(cache_location='/my/other/directory')

In this last example, caching will be enabled and the cache will be stored in ``/my/other/directory/.ossindex``.

Authenticating to OSS Index
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

By default, this library will attempt authenticated calls to OSS Index if authentication credentials exist in
``$HOME/.oss-index.config``.

``.oss-index.config`` is a YAML formatted file and the example below shows how a username and password can be added to
enable authenticated calls to OSS Index:

.. code-block::

   username: my-oss-index-username
   password: my-oss-index-password