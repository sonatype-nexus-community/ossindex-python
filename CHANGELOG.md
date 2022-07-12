# Changelog

<!--next-version-placeholder-->

## v1.1.0 (2022-07-12)
### Feature
* Support providing authentication directly over loading from configuration file ([`1bda4a9`](https://github.com/sonatype-nexus-community/ossindex-python/commit/1bda4a94e00fca30cf7488f1cb1e1bfaadaf1676))
* Support providing authentication directly over loading from configuration file ([`bcd86cb`](https://github.com/sonatype-nexus-community/ossindex-python/commit/bcd86cb70a6e889d5b34d9fdb2c58f77684f7b6d))

## v1.0.0 (2022-03-10)
### Feature
* Adopted PEP-561 #4 ([`f4b8b01`](https://github.com/sonatype-nexus-community/ossindex-python/commit/f4b8b0172fabfb55362450487d9cddaeaed3dc92))
* Added support for authentication to OSS Index #1 ([`aa26387`](https://github.com/sonatype-nexus-community/ossindex-python/commit/aa263872aeeb0ce3aa6c93de11107397f72cfb0b))
* Re-worked how we use TinyDB to attempt to resolve #2 ([`d5564da`](https://github.com/sonatype-nexus-community/ossindex-python/commit/d5564da8aaa207806e4a04db94c247ceec5fec2b))

### Fix
* Typo in `requirements.lowest.txt` ([`696f770`](https://github.com/sonatype-nexus-community/ossindex-python/commit/696f770052486fcc194a686f06ca5b47ff1f1a23))
* Potential fix for #2 ([`46f705d`](https://github.com/sonatype-nexus-community/ossindex-python/commit/46f705d117de799443902c2cb312f03b61a1ab44))
* Bug in deserialisation from cache database resolved ([`e3b9a9d`](https://github.com/sonatype-nexus-community/ossindex-python/commit/e3b9a9d74c541dead24aad90a0046fae078affca))
* Typing and imports ([`31a7e37`](https://github.com/sonatype-nexus-community/ossindex-python/commit/31a7e37e334301896f8275fb3e4f90119c05185b))

### Breaking
* #4 ([`f4b8b01`](https://github.com/sonatype-nexus-community/ossindex-python/commit/f4b8b0172fabfb55362450487d9cddaeaed3dc92))

## v0.2.1 (2021-09-16)
### Fix
* Typo in README ([`a260e91`](https://github.com/sonatype-nexus-community/ossindex-python/commit/a260e912227895d42b01a4775e36e7124fbc6f0b))

## v0.2.0 (2021-09-15)
### Feature
* Added accessor methods to Vulnerability class + helper method on OssIndexComponent to get the overriding maximum CVSS Score ([`15870a1`](https://github.com/sonatype-nexus-community/ossindex-python/commit/15870a19c7e62efb7f1c10f8f785f9d272152fc9))

### Fix
* Test corrected as was wrong ([`669ec24`](https://github.com/sonatype-nexus-community/ossindex-python/commit/669ec2481e6bbf46337e10149086c2b1fbba10e3))
* Corrected typing for OSS Index URL ([`813e593`](https://github.com/sonatype-nexus-community/ossindex-python/commit/813e593ef940cb27430590f80e2ad8628333fb2a))
* Removed garbage typo ([`23e7425`](https://github.com/sonatype-nexus-community/ossindex-python/commit/23e7425fddf104b332865f4382a9e4d857e76c04))
* Correct logic for determining which Vulnerability has the highest CVS score ([`37e5aed`](https://github.com/sonatype-nexus-community/ossindex-python/commit/37e5aed6424594f6efff136c7037d1e5db28ccd5))
* Added support for cwe being optional and added support for optional cve being present ([`3efafa9`](https://github.com/sonatype-nexus-community/ossindex-python/commit/3efafa978a2c9af647b760b34e4900917372a8d9))
* Support for OSS Index not returning descriptions for components ([`8244735`](https://github.com/sonatype-nexus-community/ossindex-python/commit/82447357188ee9c4f0a8c046b9d6a00ea556c7fc))

## v0.1.1 (2021-09-13)
### Fix
* Deployment GH action ([`1d403b5`](https://github.com/sonatype-nexus-community/ossindex-python/commit/1d403b565cc61ac100e7b8fc53a9f18c55e3c793))
* **doc:** Updated documentation to reflect usage and todos. ([`0078668`](https://github.com/sonatype-nexus-community/ossindex-python/commit/0078668a76f1911b349dccd0c21cbdcfb7dc5097))
