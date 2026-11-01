# Third-Party Notices

`checksum-manifest` itself is licensed under the MIT License. See `LICENSE`.

The source package does not vendor or redistribute the third-party libraries
listed below. They are build/runtime dependencies and remain subject to their
own licenses. Prebuilt binary distributions may include shared-library copies
of some or all of these components; those binary distributions must preserve
the applicable third-party license notices and satisfy the corresponding
redistribution terms for the exact versions that are bundled.

## OpenSSL / libcrypto

- Project: OpenSSL
- License: Apache License 2.0
- Upstream: https://www.openssl.org/
- Source: https://github.com/openssl/openssl

If a prebuilt distribution bundles `libcrypto`, include the license and any
required notices from the exact OpenSSL release used to build that binary.

## Libgcrypt

- Project: Libgcrypt
- Library license: GNU Lesser General Public License, version 2.1 or later
- Upstream: https://www.gnupg.org/software/libgcrypt/
- Source: https://gnupg.org/ftp/gcrypt/libgcrypt/

Libgcrypt also contains files with additional license notices. If a prebuilt
binary distribution bundles Libgcrypt, include the `COPYING.LIB` and `LICENSES`
files from the exact Libgcrypt source release used for that binary and satisfy
the corresponding-source obligations of the LGPL.

## Libgpg-error

- Project: Libgpg-error
- Library license: GNU Lesser General Public License, version 2.1 or later
- Upstream: https://www.gnupg.org/software/libgpg-error/
- Source: https://gnupg.org/ftp/gcrypt/libgpg-error/

If a prebuilt binary distribution bundles Libgpg-error, include the applicable
license notices from the exact source release used and satisfy the
corresponding-source obligations of the LGPL.

## RHash / LibRHash

- Project: RHash
- License: BSD Zero Clause License (0BSD)
- Upstream: https://github.com/rhash/RHash

If a prebuilt binary distribution bundles LibRHash, preserve the copyright and
license notice from the exact RHash release used.

## Binary Release Note

The MIT License for `checksum-manifest` does not replace or modify the licenses
of bundled third-party components. Linux `.so` files and Windows `.dll` files
remain under their respective upstream licenses.
