# Checksum Manifest Utility — C

`checksum-manifest` is a standalone C99 command-line utility for hashing files directly and for generating, verifying, deriving, reformatting, joining, splitting, and removing checksum manifests.

All hashing is performed in-process through OpenSSL Crypto, Libgcrypt, and LibRHash. The program does not invoke external checksum executables.

## Contents

- [Requirements](#requirements)
- [Building](#building)
  - [Direct compiler build](#direct-compiler-build)
  - [CMake](#cmake)
  - [Meson](#meson)
- [Usage](#usage)
- [Modes](#modes)
  - [check](#check)
  - [hash](#hash)
  - [generate](#generate)
  - [derive](#derive)
  - [format](#format)
  - [join](#join)
  - [split](#split)
  - [remove](#remove)
- [Algorithms and selectors](#algorithms-and-selectors)
- [Manifest discovery](#manifest-discovery)
- [Hash and generate file selection](#hash-and-generate-file-selection)
- [Entry grammar](#entry-grammar)
- [Delimiter option](#delimiter-option)
- [Verification results](#verification-results)
- [Native hash providers](#native-hash-providers)
- [Output behavior](#output-behavior)
  - [check output](#check-output)
  - [hash output](#hash-output)
  - [generate output](#generate-output)
  - [derive output](#derive-output)
  - [format behavior](#format-behavior)
  - [join output](#join-output)
  - [split output](#split-output)
  - [remove behavior](#remove-behavior)
  - [Collision handling](#collision-handling)
- [Newline modes](#newline-modes)
- [Path separators](#path-separators)
- [Absolute paths](#absolute-paths)
- [Filename encoding](#filename-encoding)
- [Memory safety](#memory-safety)
- [Signals and cleanup](#signals-and-cleanup)
- [Exit status](#exit-status)
- [Examples](#examples)
- [License](#license)

## Requirements

- A C99 compiler or newer.
- OpenSSL 1.1.0 or newer development headers and the Crypto library.
- Libgcrypt development headers and library.
- LibRHash development headers and library.
- CMake 3.10 or newer when using CMake.
- Meson 0.54 or newer when using Meson.

OpenSSL versions older than 1.1.0 are not supported; the source and both build systems enforce this minimum. All three hashing libraries are link-time dependencies. Runtime algorithm availability is still probed because an installed library version may not provide every algorithm in the registry.

The automatic native provider order is:

```text
OpenSSL -> Libgcrypt -> LibRHash
```

A provider that does not actually support the requested algorithm is skipped.

## Building

### Direct compiler build

With OpenSSL 1.1.0+ and the other dependencies in the compiler's normal search paths:

```sh
gcc -std=c99 -O2 -Wall -Wextra -Wpedantic checksum-manifest.c -o checksum-manifest -lcrypto -lgcrypt -lrhash
```

The same command works with Clang by replacing `gcc` with `clang`.

On MinGW the output name can be made explicit:

```sh
gcc -std=c99 -O2 -Wall -Wextra -Wpedantic checksum-manifest.c -o checksum-manifest.exe -lcrypto -lgcrypt -lrhash
```

With explicit include and library directories:

```sh
gcc -std=c99 -O2 -Wall -Wextra -Wpedantic \
  -I/opt/openssl/include \
  -I/opt/libgcrypt/include \
  -I/opt/rhash/include \
  checksum-manifest.c -o checksum-manifest \
  -L/opt/openssl/lib \
  -L/opt/libgcrypt/lib \
  -L/opt/rhash/lib \
  -lcrypto -lgcrypt -lrhash
```

GCC/Clang compiler search variables can also be used. For example:

```sh
export CPATH=/opt/openssl/include:/opt/libgcrypt/include:/opt/rhash/include
export LIBRARY_PATH=/opt/openssl/lib:/opt/libgcrypt/lib:/opt/rhash/lib

gcc -std=c99 -O2 -Wall -Wextra -Wpedantic checksum-manifest.c -o checksum-manifest -lcrypto -lgcrypt -lrhash
```

On Windows, use the native environment-variable list separator (`;`). For example in `cmd.exe`:

```bat
set CPATH=C:\openssl\include;C:\libgcrypt\include;C:\RHash-1.4.6\librhash
set LIBRARY_PATH=C:\openssl\lib;C:\libgcrypt\lib;C:\RHash-1.4.6\librhash

gcc -std=c99 -O2 -Wall -Wextra -Wpedantic checksum-manifest.c -o checksum-manifest.exe -lcrypto -lgcrypt -lrhash
```

Each include entry must be the directory the compiler searches directly. In particular, the LibRHash include entry normally points to the directory that contains `rhash.h` itself (for the upstream source tree that is typically `RHash-1.4.6\librhash`).

### CMake

Automatic discovery:

```sh
cmake -S . -B build
cmake --build build
```

Normal CMake discovery requires OpenSSL 1.1.0 or newer. The same minimum is checked when custom OpenSSL include/library overrides are used.

CMake accepts an include directory, an exact library file, or a library search directory for every backend:

```text
CM_OPENSSL_INCLUDE_DIR
CM_OPENSSL_LIBRARY_DIR
CM_OPENSSL_LIBRARY

CM_GCRYPT_INCLUDE_DIR
CM_GCRYPT_LIBRARY_DIR
CM_GCRYPT_LIBRARY

CM_RHASH_INCLUDE_DIR
CM_RHASH_LIBRARY_DIR
CM_RHASH_LIBRARY
```

Example using exact library files:

```sh
cmake -S . -B build \
  -DCM_OPENSSL_INCLUDE_DIR=/opt/openssl/include \
  -DCM_OPENSSL_LIBRARY=/opt/openssl/lib/libcrypto.so \
  -DCM_GCRYPT_INCLUDE_DIR=/opt/libgcrypt/include \
  -DCM_GCRYPT_LIBRARY=/opt/libgcrypt/lib/libgcrypt.so \
  -DCM_RHASH_INCLUDE_DIR=/opt/rhash/include \
  -DCM_RHASH_LIBRARY=/opt/rhash/lib/librhash.so

cmake --build build
```

Example using library directories:

```sh
cmake -S . -B build \
  -DCM_OPENSSL_INCLUDE_DIR=/opt/openssl/include \
  -DCM_OPENSSL_LIBRARY_DIR=/opt/openssl/lib \
  -DCM_GCRYPT_INCLUDE_DIR=/opt/libgcrypt/include \
  -DCM_GCRYPT_LIBRARY_DIR=/opt/libgcrypt/lib \
  -DCM_RHASH_INCLUDE_DIR=/opt/rhash/include \
  -DCM_RHASH_LIBRARY_DIR=/opt/rhash/lib

cmake --build build
```

For GCC/Clang workflows, the project also imports `CPATH`, `C_INCLUDE_PATH`, and `LIBRARY_PATH` as CMake discovery hints. This is intentional: those are compiler search variables, whereas CMake normally documents its own `CMAKE_INCLUDE_PATH` and `CMAKE_LIBRARY_PATH` search variables. With this project, the same environment used by a successful direct GCC/Clang build is also added to CMake's dependency search. CMake-native `CMAKE_INCLUDE_PATH`, `CMAKE_LIBRARY_PATH`, and `CMAKE_PREFIX_PATH` remain supported normally.

On MinGW, the `CPATH` entry for LibRHash must point to the directory containing `rhash.h`; for an unpacked RHash 1.4.6 tree this is normally `C:\RHash-1.4.6\librhash`. The `LIBRARY_PATH` entry must point to the directory containing the link library/import library.

### Meson

Meson verifies that the selected OpenSSL headers are version 1.1.0 or newer before creating the build target.

Normal discovery:

```sh
meson setup build
meson compile -C build
```

Project-specific options are available again for non-standard SDK layouts:

```text
openssl_include_dir
openssl_library_dir
openssl_library

gcrypt_include_dir
gcrypt_library_dir
gcrypt_library

rhash_include_dir
rhash_library_dir
rhash_library
```

Example:

```sh
meson setup build \
  -Dopenssl_include_dir=/opt/openssl/include \
  -Dopenssl_library_dir=/opt/openssl/lib \
  -Dgcrypt_include_dir=/opt/libgcrypt/include \
  -Dgcrypt_library_dir=/opt/libgcrypt/lib \
  -Drhash_include_dir=/opt/rhash/include \
  -Drhash_library_dir=/opt/rhash/lib

meson compile -C build
```

Exact library files may be supplied instead of library directories:

```sh
meson setup build \
  -Dopenssl_include_dir=/opt/openssl/include \
  -Dopenssl_library=/opt/openssl/lib/libcrypto.so \
  -Dgcrypt_include_dir=/opt/libgcrypt/include \
  -Dgcrypt_library=/opt/libgcrypt/lib/libgcrypt.so \
  -Drhash_include_dir=/opt/rhash/include \
  -Drhash_library=/opt/rhash/lib/librhash.so

meson compile -C build
```

When no project-specific override is supplied, Meson checks headers with the configured C compiler and resolves the three libraries with the compiler's library search. GCC/Clang therefore honor `CPATH`/`C_INCLUDE_PATH` for headers and `LIBRARY_PATH` for libraries in the same environment used for direct compiler builds. Explicit `-D..._include_dir` and `-D..._library_dir` options remain the most predictable choice for unusual SDK layouts and cross builds.

## Usage

```text
checksum-manifest check ALGORITHMS [OPTIONS] PATH_OR_CHECKSUM_FILE [CHECKSUM_FILE ...]
checksum-manifest c ALGORITHMS [OPTIONS] PATH_OR_CHECKSUM_FILE [CHECKSUM_FILE ...]
checksum-manifest hash ALGORITHMS [OPTIONS] PATH
checksum-manifest h ALGORITHMS [OPTIONS] PATH
checksum-manifest generate ALGORITHMS [OPTIONS] PATH
checksum-manifest g ALGORITHMS [OPTIONS] PATH
checksum-manifest derive ALGORITHMS --from SOURCE_ALGORITHMS [OPTIONS] PATH
checksum-manifest d ALGORITHMS --from SOURCE_ALGORITHMS [OPTIONS] PATH
checksum-manifest format ALGORITHMS [OPTIONS] PATH
checksum-manifest f ALGORITHMS [OPTIONS] PATH
checksum-manifest join ALGORITHMS [OPTIONS] PATH
checksum-manifest j ALGORITHMS [OPTIONS] PATH
checksum-manifest split ALGORITHM [OPTIONS] CHECKSUM_FILE
checksum-manifest s ALGORITHM [OPTIONS] CHECKSUM_FILE
checksum-manifest remove ALGORITHMS [OPTIONS] PATH
checksum-manifest r ALGORITHMS [OPTIONS] PATH
checksum-manifest (-h | --help | -v | --version)
```

The first argument is the mode. `c`, `h`, `g`, `d`, `f`, `j`, `s`, and `r` are aliases for `check`, `hash`, `generate`, `derive`, `format`, `join`, `split`, and `remove`.

Long options that take a value accept both `--option VALUE` and `--option=VALUE`. Use `--` to end option parsing before a positional path that begins with `-`.

```text
-r, --recursive
-o, --output PATH
-F, --from ALGORITHMS
-d, --delimiter VALUE
-n, --newline MODE
-s, --path-separator MODE
-t, --tools SPEC
-f, --filter PATTERN
-C, --filter-case MODE
-D, --digest-only
-l, --layout MODE
-N, --natural-sort
-L, --lexicographic-sort
-T, --update-timestamp
-b, --backup
-h, --help
-v, --version
```

Option applicability:

- `--recursive`: `check`, `hash`, `generate`, `derive`, `format`, `join`, `remove`; invalid with `split`.
- `--output`: `check`, `hash`, `generate`, `derive`, `join`, `split`; invalid with `format` and `remove`.
- `--from`: required by `derive`; invalid in every other mode.
- `--delimiter`, `--newline`, `--path-separator`: every mode except `remove`.
- `--tools`: `check`, `hash`, `generate`, `derive` only.
- `--filter`, `--filter-case`: `hash` and `generate` only. `--filter-case` requires explicit `--filter`.
- `--digest-only`: `hash` only.
- `--layout`: `generate` only.
- `--natural-sort`, `--lexicographic-sort`: `hash`, `generate`, `join`, `derive`; for `generate`, `--layout single` is required. The two sort options are mutually exclusive.
- `--update-timestamp`: `derive`, `format`, `remove` only.
- `--backup`: `format` only.

## Modes

### check

`check` discovers selected manifests and verifies every recognized entry.

```sh
checksum-manifest check md5 /data
checksum-manifest check md5 /data/set1.md5 /data/set2.md5
checksum-manifest c md5,sha256 -r /data
```

`check` accepts one directory, one explicit manifest file, or multiple explicit manifest files. When exactly one algorithm is selected, every explicit file is parsed as that algorithm regardless of its filename extension. With multiple algorithms or `all`, every explicit file must have a case-insensitive filename extension matching one of the selected algorithms so the algorithm can be determined unambiguously. Directory discovery always remains extension-based. When multiple inputs are supplied, every input must be a regular file; mixed file/directory input and multiple directories are rejected. Duplicate explicit file paths resolve to one verification pass. `--recursive` applies when the single input is a directory.

For each selected algorithm that has at least one discovered manifest, one native provider is selected before verification starts and is used for the whole run. A provider failure during hashing is reported as `ERROR`; provider selection is not changed mid-run.

### hash

`hash` calculates digests and writes hash output directly to stdout. Alias: `h`. It accepts the same built-in algorithm selectors as `generate`, including `all` and the `sfv` alias for `crc32`.

```sh
checksum-manifest hash sha256 /data/file.bin
checksum-manifest hash sha256 -D /data/file.bin
checksum-manifest h md5,sha256 -r -f '*.bin' /data
checksum-manifest hash sha256 -r -o hashes.txt /data
```

Without `-D/--digest-only`, one selected algorithm uses that algorithm's normal manifest record grammar. With multiple algorithms, output is file-major and algorithms appear in selector order; each standard record is prefixed with an aligned algorithm tag:

```text
[md5]     abc...  file.bin
[sha256]  def...  file.bin
```

CRC32/CRC32C keep their normal filename-first record grammar after the tag. With `-D/--digest-only`, a single algorithm writes only the hexadecimal digest. Multiple algorithms retain the same aligned algorithm tag but omit the filename and manifest record formatting:

```text
[md5]     abc...
[sha256]  def...
```

Digest-only output remains file-major and follows selector order. `--delimiter` and `--path-separator` are accepted but do not affect digest-only output. Without `--digest-only`, output paths are relative to the input root: a file input uses its basename, while directory input preserves paths below that directory. `--path-separator` controls rendering.

`hash` prints no `Tools:`, `Entries:`, summary, completion message, or output-path status on stdout; stdout contains hash output only. Diagnostics go to stderr. `-o/--output` writes the same output byte stream to one collision-safe file instead of stdout. If a collision selects a different `-o` pathname, the actual pathname is reported on stderr. Each emitted record ends with the selected newline, so non-empty redirected or `-o` output ends with a newline. Early downstream pipe closure is treated as normal successful termination.

The supported options are `-r/--recursive`, `-o/--output`, `-d/--delimiter`, `-n/--newline`, `-s/--path-separator`, `-t/--tools`, `-f/--filter`, `-C/--filter-case`, `-D/--digest-only`, `-N/--natural-sort`, and `-L/--lexicographic-sort`. Their defaults match `generate` where applicable: filter `*`, case-sensitive matching, Unix newlines, slash path separators, automatic provider selection, and normal bytewise discovery order unless a sort option is selected.

If one file or one algorithm fails to hash, the error is written to stderr, remaining work continues, successful records are retained, and the final status is nonzero.

### generate

`generate` hashes regular files and writes checksum manifests.

```sh
checksum-manifest generate md5 /data
checksum-manifest g md5,sha256 -r -f '*.zip' /data
```

The default filter is `*`, matching is case-sensitive, and the default layout is `separate`.

`-f/--filter` accepts a portable shell-style basename pattern. `-C/--filter-case` selects `sensitive` or `insensitive`; it requires explicit `--filter`. ASCII case folding is used in insensitive mode.

`-l/--layout` accepts:

- `separate`: one manifest per source file and algorithm; the default.
- `single`: one combined manifest per selected algorithm.

In `single` layout, `-N/--natural-sort` and `-L/--lexicographic-sort` control discovery order inside each directory. Traversal remains depth-first; sorting is not a final global sort over the completed tree.

Natural sorting compares digit runs numerically and non-digit chunks bytewise. Lexicographic sorting is bytewise.

### derive

`derive` uses the valid entry paths in existing reference manifests to create missing target manifests and to check path coverage when a target already exists.

```sh
checksum-manifest derive sha256,sha512 -F md5,sha1 /data/releases
checksum-manifest d sha256 -F md5 -r -N -o /tmp/derived /data/releases
```

The positional selector is the target algorithm list. `-F/--from` selects reference-manifest extensions and is required.

Existing target manifests are never rehashed or rewritten. Their valid entry paths are compared lexically after the selected path-separator interpretation. Referenced data files do not need to exist for this comparison. Every reference occurrence must have a matching target occurrence; duplicate occurrences therefore matter. Extra target entries are allowed.

When a target is missing, one output entry is created for every valid reference entry. The missing target is written only if every required source file can be represented, read, and hashed, so a partial target manifest is not committed. `-N` or `-L` can reorder valid reference entries before creation.

When several reference algorithms with the same stem could create the same missing target, `--from` order is the creation precedence. Later references compare against the target already created.

Status labels are:

- `OUTPUT`: a missing target was created.
- `COMPLETE`: an existing target covers all reference occurrences.
- `INCOMPLETE`: an existing target is missing at least one reference occurrence.
- `MISSING`: one reference occurrence is not covered by an existing target.

By default, a newly created target copies the reference manifest modification time and target-directory modification times are preserved best-effort. `-T/--update-timestamp` leaves these times to normal filesystem behavior.

### format

`format` rewrites selected manifest formatting without recalculating digests.

Before scanning/rewrite begins it prints a plan and requires explicit `y` or `yes` confirmation, case-insensitively. Any other answer cancels with success and no rewrite.

Recognized entry formatting may change according to delimiter, newline, and path-separator options. Digest text and non-entry lines are preserved. A manifest containing NUL is refused. Symbolic-link manifest paths are not rewritten.

With `-b/--backup`, a collision-safe `.cmbak` backup is created before the manifest is rewritten. Backup creation failure prevents that manifest from being rewritten. A backup is still created when the resulting formatted content is unchanged.

Without `-T`, manifest, backup, and scanned-directory modification times are preserved best-effort. `-T` leaves timestamp changes to normal filesystem behavior.

### join

`join` combines valid entries from selected manifests into one output per algorithm.

```sh
checksum-manifest join sha256 -r /data
checksum-manifest join sha256 -r -L -o /tmp/checksums.sha256 /data
```

Entry paths are rebased relative to the `PATH` source base: when `PATH` is a directory, they are relative to that directory; when `PATH` is a manifest file, they are relative to that manifest's parent directory. Supplying `-o/--output` changes only where the joined manifest is written; it does not rebase entry paths relative to the output location. Discovery can use natural or lexicographic ordering.

For each algorithm, output is all-or-nothing: an unreadable selected manifest, a selected manifest with zero valid entries, or an unrepresentable required path prevents that algorithm's joined output from being committed.

### split

`split` requires exactly one algorithm/extension selector and one combined manifest file. `all` and `--recursive` are invalid.

```sh
checksum-manifest split sha256 checksums.sha256
checksum-manifest split shake256 -o /tmp/split checksums.shake256
```

Each valid input entry is written to the corresponding per-entry manifest. Records that map to the same output manifest are grouped together. Entry paths are rebased relative to each newly created manifest.

Without `-o`, outputs are confined below the input manifest directory. Absolute entries and escaping parent-relative entries are rejected. With `-o DIR`, absolute entries are re-rooted below `DIR`; escaping parent-relative entries are still rejected. Existing parent components are checked so a symbolic link cannot redirect output outside the safety root.

`split` can have partial success: safe entries may be written while invalid/escaping entries are reported as errors.

### remove

`remove` deletes selected manifest files after three confirmations.

The first two confirmations accept case-insensitive `y` or `yes`. The final confirmation must be exactly lowercase `yes` with no surrounding whitespace. Discovery and deletion start only after the final confirmation.

Each selected manifest is removed independently and deletion continues after individual failures. Without `-T`, parent-directory modification times changed by deletion are restored best-effort; `-T` disables that restoration.

## Algorithms and selectors

Built-in hashing algorithms:

```text
crc32, crc32c, md5, sha1, sha224, sha256, sha384, sha512,
blake2s, blake2b, blake3, whirlpool,
keccak-224, keccak-256, keccak-384, keccak-512,
sha3-224, sha3-256, sha3-384, sha3-512
```

`check`, `hash`, `generate`, and the target selector of `derive` require built-in hashing algorithms.

`format`, `join`, `split`, `remove`, and `derive -F/--from` also accept explicit custom algorithm/extension names matching:

```text
[A-Za-z0-9][A-Za-z0-9._+-]*
```

Matching is case-insensitive using ASCII folding.

`all` is a standalone case-insensitive keyword and cannot be combined with other comma-separated names. For built-in target selection it expands to the full built-in list. For transform/reference selectors it expands to the same built-in extension list; it does not discover arbitrary unknown extensions. `split` requires exactly one selector and rejects `all`.

`sfv` is a reserved case-insensitive alias for `crc32`. CRC32 uses `.sfv`; CRC32C uses `.crc32c`; every other built-in algorithm uses `.<algorithm>`.

Duplicate selector names are ignored after normalization.

## Manifest discovery

Manifest extension matching is case-insensitive:

```text
FILE.MD5
file.Md5
file.md5
```

are all discovered as MD5 manifests.

CRC32 discovery uses `.sfv`; `.crc32` is not a CRC32 manifest.

For `check`, when exactly one algorithm is selected, an explicit manifest file is parsed as that algorithm regardless of its filename extension. With multiple algorithms or `all`, explicit files require a case-insensitive extension matching one of the selected algorithms for disambiguation. Directory discovery remains extension-based in all cases.

Without `--recursive`, only the supplied directory is scanned. With it, subdirectories are scanned depth-first. Hidden files and directories are included. Directory symlinks encountered during traversal are not followed. If the supplied starting path itself resolves to a directory, that starting directory is accepted.

Unreadable/unsearchable directories are operational errors and produce a nonzero final status.

## Hash and generate file selection

`hash` and `generate` accept an existing regular file or directory.

The filter is applied to each source basename and supports the portable subset:

- `*`
- `?`
- bracket expressions such as `[abc]` and `[!abc]`
- ranges
- POSIX bracket classes
- backslash escaping

Extended glob operators are not part of the contract.

Examples:

```text
*
*.zip
backup-?.tar
[ABC]*.iso
```

In case-insensitive mode, ASCII letters are folded. `[[:upper:]]` and `[[:lower:]]` both behave like ASCII `[[:alpha:]]`. Non-ASCII case equivalents are not folded.

Generated manifests and `hash -o` output files are ordinary files on later scans. If an old output is inside the scanned tree and matches the active filter, it can become a source file on a later `hash` or `generate` run.

## Entry grammar

`check`, `derive`, `format`, `join`, and `split` share the same parser.

For non-CRC algorithms the recognized form is conceptually:

```regex
^([A-Fa-f0-9]+)(  | \*|\t\*| |\t)(.+)$
```

Accepted digest/filename separators are:

```text
<space><space>
<space>*
<TAB>*
<space>
<TAB>
```

The parser backtracks on ambiguous delimiters so the filename must remain non-empty.

CRC32 and CRC32C are filename-first:

```text
FILENAME<one-or-more-spaces-or-tabs>DIGEST
```

Because whitespace is the field separator, a CRC filename ending in a space or tab is inherently ambiguous.

Digest characters must be hexadecimal, but digest length is intentionally not validated by the parser.

Blank lines and unescaped lines beginning with `#` or `;` are ignored. `check`, `derive`, `join`, and `split` skip unrecognized lines and NUL-containing lines. `format` refuses to rewrite a manifest containing NUL but preserves other non-entry text.

Escaped records decode these filename sequences:

```text
\\   literal backslash
\n   LF
\r   CR
```

A selected manifest with zero valid entries is an error in `check`, `join`, and `split`. In `derive`, a reference/source manifest with zero valid entries is an error, but an existing target manifest with zero valid entries remains a valid comparison target: a non-empty reference will report its occurrences as `MISSING` and the target as `INCOMPLETE`. `format` may process a zero-entry manifest because non-entry text is preserved/reformatted as appropriate.

## Delimiter option

For every non-CRC algorithm, `-d/--delimiter` accepts exactly:

```text
<space><space>
<space>*
```

Shell examples normally quote these as `'  '` and `' *'`.

The default is two spaces. `generate`, `derive`, `format`, `join`, and `split` use the selected delimiter when writing non-CRC records. `check` recognition is independent of the selected output delimiter.

For CRC32/CRC32C the option is accepted but ignored; CRC output uses its filename-first single-space form.

## Verification results

`check` uses these labels:

```text
[VALID]:   ./a/b.tar.gz [sha256]
[INVALID]: ./f/e/c.tar.gz [md5]
[UNREAD]:  ./missing.iso [sha256]
[ERROR]:   ./problem.bin [md5]
```

- `VALID`: calculated digest matches.
- `INVALID`: hashing succeeded but the digest does not match.
- `UNREAD`: target is missing, not a regular file, or not readable.
- `ERROR`: another verification/hash/provider error occurred.

Each checked-file result ends with the normalized lowercase algorithm in brackets. `Entries:` counts parsed entries by algorithm, including failed checks; manifest-level errors are not entry counts.

`Tools:` reports the native provider selected for each algorithm that actually required hashing.

## Native hash providers

Hashing is always in-process. No external executable is launched.

Automatic provider preference is:

```text
OpenSSL -> Libgcrypt -> LibRHash
```

For each algorithm that actually requires hashing, provider availability is probed at runtime. A linked provider can therefore be skipped when that provider/library version lacks the requested algorithm.

Use `-t/--tools` with `check`, `hash`, `generate`, or `derive` to pin a provider:

```sh
checksum-manifest generate md5,sha256 \
  -t 'md5:librhash,sha256:openssl' /data
```

Specification format:

```text
ALGORITHM:PROVIDER[,ALGORITHM:PROVIDER...]
```

Provider names:

```text
openssl
libgcrypt
gcrypt
librhash
rhash
```

`gcrypt` normalizes to `libgcrypt`; `rhash` normalizes to `librhash`. `sfv` may be used where `crc32` is selected and normalizes to CRC32.

A pinned algorithm does not fall back. Unlisted algorithms use automatic provider selection. A pin that is structurally impossible according to the central algorithm registry is rejected during command-line validation.

`format`, `join`, `split`, and `remove` do not hash file contents and do not require runtime provider selection. `derive` requires providers only for target manifests that are missing and must actually be created.

## Output behavior

On POSIX, files newly created by `check -o`, `hash -o`, `generate`, `derive`, `join`, and `split` are normalized to mode `0644`. Hash output redirected by the shell to a regular stdout file (for example `> hashes.txt`) is also normalized to mode `0644`; pipes are not chmodded. `format` preserves existing manifest permission bits and `.cmbak` backups preserve source permissions. Other metadata such as inode identity, ownership, ACLs, extended attributes, security labels, capabilities, and hard-link topology is not guaranteed when a manifest is atomically replaced.

### check output

```sh
checksum-manifest check sha256 -o report.txt /data
```

The report contains verification lines, `Tools:`, per-algorithm `Entries:`, and `Summary:`. The terminal reports the actual collision-safe report path.

With multiple explicit manifest inputs, displayed target paths are based on the current working directory; file resolution itself remains relative to each individual manifest directory.

### hash output

Without `-o`, `hash` writes records to stdout and nothing else. Shell redirection such as `checksum-manifest hash sha256 PATH > hashes.txt` therefore captures the same bytes that `-o hashes.txt` would write when no collision changes the `-o` pathname.

With one algorithm the stream is standard manifest grammar. With multiple algorithms each line starts with an aligned `[algorithm]` tag, and records are ordered file-major with algorithms in selector order. Paths are relative to the input root, not to the current directory or the `-o` file location. If stdout is redirected to a regular file inside a scanned directory input, that stdout file is excluded from hash input discovery so it does not hash itself. Do not redirect stdout directly onto the input file itself: the shell truncates that file before the utility starts, and `hash` rejects the detected overlap.

`-o/--output` preserves an existing destination and selects a report-style collision-safe pathname such as `hashes-A1B2C3D4.txt`. When a collision selects an alternate pathname, that actual path is reported on stderr. Shell `>` redirection is controlled by the shell and therefore does not use the utility's collision-safe naming.

### generate output

`Entries:` lists per-algorithm counts and a total.

With default `separate` layout and no `-o`, one manifest is created beside each source file for each selected algorithm. A collision preserves the existing file and adds an eight-character hexadecimal suffix before the checksum extension:

```text
archive.zip.md5
archive.zip-A1B2C3D4.md5
```

With `separate -o DIR`, `DIR` is created as needed and the source tree is recreated below it. Generated records refer back to their source using relative paths.

With `single` layout, one combined manifest is generated per selected algorithm. Without `-o`, outputs are placed in the supplied directory or beside a supplied source file:

```text
checksums.md5
checksums.sha256
checksums.sfv
```

A default-name collision produces, for example:

```text
checksums-A1B2C3D4.sha256
```

For one selected algorithm, `single -o` may be an existing directory or an explicit output file with the expected extension. For multiple algorithms, `-o` must be an existing directory.

If discovery succeeds and the filter selects zero files, `generate` succeeds with zero files/entries/outputs and does not require provider selection.

### derive output

Without `-o`, missing targets are written beside their reference manifests using the same stem and target extension. With `-o DIRECTORY`, the reference manifest's relative subdirectory structure is mirrored below the output root. Entry text is not rebased merely because an output root was supplied.

Existing targets are compared and never rewritten. Missing targets use their semantic target path; `derive` does not substitute a random collision name.

By default, a newly created target attempts to copy the reference manifest mtime and preserves affected target-directory mtimes best-effort. `-T` disables this preservation.

### format behavior

`format` rewrites at the original pathname. When content changes, a temporary file in the same directory is written and atomically replaces the old pathname. Permission bits are preserved. The original inode and non-permission metadata are not guaranteed to survive replacement.

Without `-T`, modification times of manifests, backups, and scanned directories are preserved best-effort. Preservation failures are aggregated as warnings rather than stopping formatting.

With `-b`, `.cmbak` is created before rewrite. Collision-safe naming preserves an existing backup.

### join output

Without `-o`, joined outputs are placed in `PATH` when it is a directory, or beside `PATH` when `PATH` is a manifest file.

Default names are:

```text
checksums.md5
checksums.sha256
checksums.sfv
checksums.crc32c
```

With one algorithm, `-o` may be an existing directory or an explicit output file with the expected extension. With multiple algorithms, `-o` must be an existing directory.

If a selected manifest for one algorithm is unreadable or contains zero valid entries, that algorithm's output is not committed.

### split output

Without `-o`, outputs are confined below the input manifest directory. With `-o DIR`, the entry tree is recreated below `DIR`, including safe re-rooting of absolute entries.

Lexical containment and existing-parent checks prevent `..` and symbolic-link escape outside the output root.

Collisions preserve existing output files and insert an eight-character hexadecimal suffix before the checksum extension.

### remove behavior

`remove` creates no output files. After final confirmation, each selected manifest is unlinked independently. Errors do not stop later deletions. Without `-T`, affected parent directory mtimes are restored best-effort.

### Collision handling

Existing output files are never silently overwritten by `check -o`, `generate`, `join`, or `split`.

Report example:

```text
report.txt -> report-A1B2C3D4.txt
```

Manifest examples:

```text
archive.zip.md5 -> archive.zip-A1B2C3D4.md5
checksums.sha256 -> checksums-92AF01CC.sha256
movie.mkv.sfv -> movie.mkv-1122AABB.sfv
```

For generic `join` collision names, the output form is:

```text
checksum-A1B2C3D4.md5
checksum-92AF01CC.sfv
```

`derive` intentionally does not use random collision substitution because its target pathname has semantic meaning.

## Newline modes

`-n/--newline` is case-insensitive:

| Values | Output newline |
|---|---|
| `unix`, `lf` | LF |
| `windows`, `crlf` | CRLF |
| `classic-mac`, `cr` | CR |
| `system` | native platform newline |

Default: `unix` / LF.

Input manifests can contain LF, CRLF, or CR. The option controls newly written reports/manifests and `format` output.

## Path separators

`-s/--path-separator` accepts, case-insensitively:

```text
slash
backslash
default
system
```

Default: `slash`.

Mode-dependent meaning:

- `generate`: controls separator style written into generated relative entry paths.
- `check`, `join`, `split`: controls interpretation of path text read from manifests.
- `derive`: controls reference path interpretation and the representation of newly created target entries. The default `slash` mode treats both slash characters as separator markers and writes `/`.
- `format`: `default` preserves existing separator characters. `slash`, `backslash`, and `system` are textual normalization modes that treat both `/` and `\` as separator markers and rewrite them to the requested/native style.

On systems where a literal backslash is legal inside a filename, forced separator normalization is inherently ambiguous. Use `default` when existing separator characters must be preserved literally.

## Absolute paths

Absolute manifest entry paths are accepted by `check`, `derive`, `format`, and `join`.

`split` accepts an absolute entry only with `-o`, where it is re-rooted safely below the output directory. Without `-o`, absolute and escaping parent-relative entries are rejected.

The mode input `PATH` itself may be absolute.

Generated `generate` records are normally relative to their manifest location.

## Filename encoding

On POSIX, path handling is byte-oriented so filenames containing bytes that are not valid UTF-8 can still be scanned, hashed, represented, and round-tripped where the manifest format permits.

On Windows, command-line and filesystem operations use wide Win32 paths internally and convert UTF-16 to/from UTF-8 for the program's internal textual representation.

The portable hash/generate filter operates on filename bytes. `?` matches one filesystem byte, not one Unicode code point. Literal non-ASCII filter text is matched using its encoded bytes; Unicode case folding is not performed.

## Memory safety

Memory management is centralized and defensive. Dynamic buffers, vectors, and allocation-size calculations use checked size arithmetic so size growth cannot silently wrap `size_t` before allocation, and owned heap resources have explicit cleanup paths.

## Signals and cleanup

`SIGINT` and `SIGTERM` request cooperative cancellation. Hashing/writing loops observe the signal state, temporary files and reserved collision paths are cleaned, and the process exits with `128 + signal` when interruption is observed. Normal `Operation complete.` summaries are suppressed after interruption, and no cancellation or interruption message is printed.

A partially written `check` report or manifest temporary file is not intentionally left as a committed output. Outputs that were already committed before a later signal are not rolled back.

## Exit status

Typical statuses:

- `0`: success, including cancellation at a confirmation prompt before destructive/rewrite work begins.
- `1`: verification mismatch/unreadable/error, manifest/data processing failure, or an operational failure after valid command-line parsing.
- `2`: command-line usage, initial path validation, or output preflight/configuration error.
- `127`: no usable native provider can be selected for an algorithm that actually requires hashing.
- `128 + signal`: interrupted by `SIGINT` or `SIGTERM`.

For `derive`, status `1` also covers missing occurrence coverage in an existing target, unreadable/unhashable source data during target creation, and ambiguous target case variants. Timestamp-preservation warnings alone do not change the exit status.

If every corresponding `derive` target already exists, no hashing provider is required.

## Examples

Verify SHA-256 manifests:

```sh
checksum-manifest check sha256 /data/releases
```

Verify all supported manifest algorithms recursively:

```sh
checksum-manifest check all -r .
```

Verify several explicit manifests:

```sh
checksum-manifest check sha256 /data/a.sha256 /data/b.sha256
```

Write a verification report:

```sh
checksum-manifest check sha256 -r -o /tmp/check-report.txt /data/releases
```

Generate MD5 and SHA-256 manifests recursively:

```sh
checksum-manifest generate md5,sha256 -r /data/releases
```

Generate SHA-256 manifests only for ISO files, case-insensitively:

```sh
checksum-manifest generate sha256 -r -f '*.iso' -C insensitive /data/releases
```

Generate one naturally ordered combined SHA-256 manifest:

```sh
checksum-manifest generate sha256 -r -l single -N -o /tmp/checksums.sha256 /data/releases
```

Use the ` *` delimiter and CRLF output:

```sh
checksum-manifest generate sha256 -d ' *' -n windows /data/releases
```

Pin native providers:

```sh
checksum-manifest generate md5,sha256 -t 'md5:librhash,sha256:openssl' /data/releases
```

Derive missing SHA-256/SHA-512 targets from MD5/SHA-1 references:

```sh
checksum-manifest derive sha256,sha512 -F md5,sha1 -r /data/releases
```

Format manifests with backups:

```sh
checksum-manifest format sha256 -r -d ' *' -n windows -s slash -b /data/releases
```

Join SHA-256 manifests recursively:

```sh
checksum-manifest join sha256 -r -L -o /tmp/joined.sha256 /data/releases
```

Join a custom `.shake256` manifest extension:

```sh
checksum-manifest join shake256 -r -o /tmp/manifests /data/releases
```

Split one combined manifest:

```sh
checksum-manifest split sha256 -o /tmp/split /tmp/joined.sha256
```

Remove SHA-256 manifests recursively after the three confirmations:

```sh
checksum-manifest remove sha256 -r /data/releases
```

Pass a positional pathname beginning with `-`:

```sh
checksum-manifest check sha256 -- -checksums.sha256
```

## License

This project is licensed under the MIT License.
