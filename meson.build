project('checksum-manifest', 'c', version: '1.1.0', meson_version: '>=0.54.0', default_options: ['c_std=c99', 'warning_level=2'])

cc = meson.get_compiler('c')
fs = import('fs')
manual_c_args = []
deps = []
manual_link_args = []

openssl_inc = get_option('openssl_include_dir')
openssl_libdir = get_option('openssl_library_dir')
openssl_lib = get_option('openssl_library')
openssl_c_args = []
if openssl_inc != ''
  if cc.get_argument_syntax() == 'msvc'
    openssl_c_args += ['/I' + openssl_inc]
  else
    openssl_c_args += ['-I' + openssl_inc]
  endif
  manual_c_args += openssl_c_args
endif
if not cc.has_header('openssl/evp.h', args: openssl_c_args)
  error('OpenSSL header openssl/evp.h not found. Set -Dopenssl_include_dir=... or configure the compiler include search path (for GCC/Clang, CPATH/C_INCLUDE_PATH).')
endif
openssl_version_test = '''
#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER < 0x10100000L
#error OpenSSL 1.1.0 or newer is required
#endif
int main(void) { return 0; }
'''
if not cc.compiles(openssl_version_test, args: openssl_c_args, name: 'OpenSSL >= 1.1.0')
  error('OpenSSL 1.1.0 or newer is required.')
endif
if openssl_lib != ''
  if not fs.exists(openssl_lib)
    error('openssl_library does not exist: ' + openssl_lib)
  endif
  manual_link_args += [openssl_lib]
elif openssl_libdir != ''
  deps += [cc.find_library('crypto', dirs: [openssl_libdir], required: true)]
else
  deps += [cc.find_library('crypto', required: true)]
endif

gcrypt_inc = get_option('gcrypt_include_dir')
gcrypt_libdir = get_option('gcrypt_library_dir')
gcrypt_lib = get_option('gcrypt_library')
gcrypt_c_args = []
if gcrypt_inc != ''
  if cc.get_argument_syntax() == 'msvc'
    gcrypt_c_args += ['/I' + gcrypt_inc]
  else
    gcrypt_c_args += ['-I' + gcrypt_inc]
  endif
  manual_c_args += gcrypt_c_args
endif
if not cc.has_header('gcrypt.h', args: gcrypt_c_args)
  error('Libgcrypt header gcrypt.h not found. Set -Dgcrypt_include_dir=... or configure the compiler include search path (for GCC/Clang, CPATH/C_INCLUDE_PATH).')
endif
if gcrypt_lib != ''
  if not fs.exists(gcrypt_lib)
    error('gcrypt_library does not exist: ' + gcrypt_lib)
  endif
  manual_link_args += [gcrypt_lib]
elif gcrypt_libdir != ''
  deps += [cc.find_library('gcrypt', dirs: [gcrypt_libdir], required: true)]
else
  deps += [cc.find_library('gcrypt', required: true)]
endif

rhash_inc = get_option('rhash_include_dir')
rhash_libdir = get_option('rhash_library_dir')
rhash_lib = get_option('rhash_library')
rhash_c_args = []
if rhash_inc != ''
  if cc.get_argument_syntax() == 'msvc'
    rhash_c_args += ['/I' + rhash_inc]
  else
    rhash_c_args += ['-I' + rhash_inc]
  endif
  manual_c_args += rhash_c_args
endif
if not cc.has_header('rhash.h', args: rhash_c_args)
  error('LibRHash header rhash.h not found. Set -Drhash_include_dir=... or configure the compiler include search path (for GCC/Clang, CPATH/C_INCLUDE_PATH).')
endif
if rhash_lib != ''
  if not fs.exists(rhash_lib)
    error('rhash_library does not exist: ' + rhash_lib)
  endif
  manual_link_args += [rhash_lib]
elif rhash_libdir != ''
  deps += [cc.find_library('rhash', dirs: [rhash_libdir], required: true)]
else
  deps += [cc.find_library('rhash', required: true)]
endif

executable('checksum-manifest', 'checksum-manifest.c',
  c_args: manual_c_args,
  dependencies: deps,
  link_args: manual_link_args,
  install: true)
