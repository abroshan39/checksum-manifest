#ifndef _WIN32
#define _XOPEN_SOURCE 700
#endif
#define _POSIX_C_SOURCE 200809L

#if defined(__clang__)
#pragma clang diagnostic ignored "-Wstrict-prototypes"
#endif

/*
 * checksum-manifest is a standalone C99 command-line utility for hashing files directly and
 * generating, verifying, deriving, reformatting, joining, splitting, and removing checksum manifests.
 *
 * Hashing is performed in-process through OpenSSL, Libgcrypt, and LibRHash.
 * No external checksum executable is invoked.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <limits.h>

#include <openssl/opensslv.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#if OPENSSL_VERSION_NUMBER < 0x10100000L
#error "checksum-manifest requires OpenSSL 1.1.0 or newer"
#endif
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/provider.h>
#endif

#include <gcrypt.h>

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#endif
#include <rhash.h>
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>

#ifndef MB_ERR_INVALID_CHARS
#define MB_ERR_INVALID_CHARS 0x00000008
#endif

#ifndef WC_ERR_INVALID_CHARS
#define WC_ERR_INVALID_CHARS 0x00000080
#endif

#include <io.h>
#include <fcntl.h>
#include <direct.h>
#include <sys/stat.h>

#define CM_SEP '\\'
#define CM_ALT_SEP '/'
#define CM_PATH_MAX 32768
#define cm_strcasecmp _stricmp
#else
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <utime.h>

#define CM_SEP '/'
#define CM_ALT_SEP '\\'
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif
#define CM_PATH_MAX PATH_MAX
#endif

#ifndef O_BINARY
#define O_BINARY 0
#endif

#define CM_VERSION "1.1.0"
#define CM_ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))
#define CM_HASH_CHUNK (64U * 1024U)
#define CM_PROGRESS_INTERVAL_MS 100ULL
#define CM_PROGRESS_STOP_TIMEOUT_MS 250UL
#define CM_RANDOM_SUFFIX_LEN 8

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#define CM_UNUSED _Static_assert(1, "")
#else
#define CM_UNUSED ((void)0)
#endif

typedef enum
{
    CM_DIGEST_FIRST = 0,
    CM_FILENAME_FIRST = 1
} CmManifestStyle;

typedef enum
{
    CM_LOWERCASE = 0,
    CM_UPPERCASE = 1
} CmDigestCase;

typedef struct
{
    const char *name;
    const char *openssl_name;
    const char *gcrypt_name;
    const char *rhash_name;
    const char *extension;
    CmManifestStyle style;
    CmDigestCase digest_case;
} CmAlgorithmInfo;

/* NULL provider names use the registry name mapping; an empty string disables that provider. */
/* NULL extensions use the algorithm name. The table is intentionally one-row-per-algorithm. */
static const CmAlgorithmInfo kAlgorithmInfo[] =
{
    /* name          OpenSSL        Libgcrypt       LibRHash    extension  manifest style     digest case */
    { "crc32",       "",            "CRC32",        "crc32",    "sfv",     CM_FILENAME_FIRST, CM_UPPERCASE },
    { "crc32c",      "",            "",             "crc32c",   NULL,      CM_FILENAME_FIRST, CM_UPPERCASE },
    { "md5",         NULL,          NULL,           NULL,       NULL,      CM_DIGEST_FIRST,   CM_LOWERCASE },
    { "sha1",        "SHA1",        "SHA1",         NULL,       NULL,      CM_DIGEST_FIRST,   CM_LOWERCASE },
    { "sha224",      "SHA224",      "SHA224",       NULL,       NULL,      CM_DIGEST_FIRST,   CM_LOWERCASE },
    { "sha256",      "SHA256",      "SHA256",       NULL,       NULL,      CM_DIGEST_FIRST,   CM_LOWERCASE },
    { "sha384",      "SHA384",      "SHA384",       NULL,       NULL,      CM_DIGEST_FIRST,   CM_LOWERCASE },
    { "sha512",      "SHA512",      "SHA512",       NULL,       NULL,      CM_DIGEST_FIRST,   CM_LOWERCASE },
    { "blake2s",     "BLAKE2s256",  "BLAKE2S_256",  "BLAKE2S",  NULL,      CM_DIGEST_FIRST,   CM_LOWERCASE },
    { "blake2b",     "BLAKE2b512",  "BLAKE2B_512",  "BLAKE2B",  NULL,      CM_DIGEST_FIRST,   CM_LOWERCASE },
    { "blake3",      NULL,          "",             NULL,       NULL,      CM_DIGEST_FIRST,   CM_LOWERCASE },
    { "whirlpool",   "WHIRLPOOL",   "WHIRLPOOL",    NULL,       NULL,      CM_DIGEST_FIRST,   CM_LOWERCASE },
    { "keccak-224",  "KECCAK-224",  "",             "",         NULL,      CM_DIGEST_FIRST,   CM_LOWERCASE },
    { "keccak-256",  "KECCAK-256",  "",             "",         NULL,      CM_DIGEST_FIRST,   CM_LOWERCASE },
    { "keccak-384",  "KECCAK-384",  "",             "",         NULL,      CM_DIGEST_FIRST,   CM_LOWERCASE },
    { "keccak-512",  "KECCAK-512",  "",             "",         NULL,      CM_DIGEST_FIRST,   CM_LOWERCASE },
    { "sha3-224",    "SHA3-224",    "SHA3-224",     NULL,       NULL,      CM_DIGEST_FIRST,   CM_LOWERCASE },
    { "sha3-256",    "SHA3-256",    "SHA3-256",     NULL,       NULL,      CM_DIGEST_FIRST,   CM_LOWERCASE },
    { "sha3-384",    "SHA3-384",    "SHA3-384",     NULL,       NULL,      CM_DIGEST_FIRST,   CM_LOWERCASE },
    { "sha3-512",    "SHA3-512",    "SHA3-512",     NULL,       NULL,      CM_DIGEST_FIRST,   CM_LOWERCASE }
};

typedef struct
{
    char **v;
    size_t n, cap;
} CmStrVec;

typedef struct
{
    char *path;
    char *algo;
} CmManifest;

typedef struct
{
    CmManifest *v;
    size_t n, cap;
} CmManifestVec;

typedef struct
{
    char *digest;
    char *name;
    char *raw_name;
    int escaped;
    size_t line_no;
} CmRecord;

typedef struct
{
    CmRecord *v;
    size_t n, cap;
} CmRecordVec;

typedef struct
{
    char *key;
    int count;
} CmCountEntry;

typedef struct
{
    CmCountEntry *v;
    size_t n, cap;
} CmCountMap;

typedef struct
{
    char *algo;
    char *provider;
} CmProviderOverride;

typedef struct
{
    CmProviderOverride *v;
    size_t n, cap;
} CmProviderOverrideVec;

typedef struct
{
    long long sec;
    long nsec;
    int valid;
} CmTimestamp;

typedef struct
{
    int exists, is_reg, is_dir, is_symlink;
    unsigned long long size;
    unsigned long mode;
    CmTimestamp mtime;

#ifndef _WIN32
    dev_t dev;
    ino_t ino;
#endif
} CmFileInfo;

typedef struct
{
    FILE *terminal;
    const char *algorithm;
    unsigned long long total;
    unsigned long long processed;
    unsigned long long last_update_ms;
    size_t line_length;
    unsigned initial_columns;
    int requested;
    int active;
    int disabled_after_resize;
#ifdef _WIN32
    void *windows_context;
#endif
} CmHashProgress;

typedef struct
{
    char *mode;
    CmStrVec algorithms;
    CmStrVec source_algorithms;
    CmStrVec check_paths;
    char *path;
    char *output;
    char *delimiter;
    char *newline_mode;
    char *path_separator;
    char *filter_pattern;
    char *filter_case;
    char *layout;
    char *tools_raw;
    CmProviderOverrideVec tools;
    int recursive;
    int natural_sort;
    int lexicographic_sort;
    int update_timestamp;
    int backup;
    int digest_only;
    int filter_explicit;
    int filter_case_explicit;
    int layout_explicit;
    int newline_explicit;
    int path_separator_explicit;
} CmOptions;

typedef struct
{
    FILE *file;
    char *path;
    int owns_file;
    int failed;
    int broken_pipe;
} CmHashOutput;

typedef enum
{
    CM_PROVIDER_AUTO = 0,
    CM_PROVIDER_OPENSSL,
    CM_PROVIDER_GCRYPT,
    CM_PROVIDER_RHASH
} CmProvider;

typedef struct
{
    const CmAlgorithmInfo *algo;
    CmProvider provider;
} CmProviderChoice;

typedef struct
{
    CmProviderChoice *v;
    size_t n, cap;
} CmProviderChoiceVec;

typedef struct
{
    char *data;
    size_t len, cap;
} CmBuf;

static volatile sig_atomic_t g_interrupted = 0;
static int g_scan_errors = 0;
static CmStrVec g_temp_paths = {0, 0, 0};
static CmStrVec g_reserved_paths = {0, 0, 0};

static void cm_signal_handler(int sig)
{
    g_interrupted = sig ? sig : 1;
}

static void cm_allocation_failure()
{
    fprintf(stderr, "Error: out of memory.\n");
    exit(2);
}

static size_t cm_size_add(size_t a, size_t b)
{
    if(b > SIZE_MAX - a)
        cm_allocation_failure();
    return a + b;
}

static size_t cm_size_mul(size_t a, size_t b)
{
    if(a != 0 && b > SIZE_MAX / a)
        cm_allocation_failure();
    return a * b;
}

static void *cm_xmalloc(size_t n)
{
    void *p = malloc(n ? n : 1);

    if(!p)
        cm_allocation_failure();
    return p;
}

static void *cm_xrealloc(void *p, size_t n)
{
    void *q = realloc(p, n ? n : 1);

    if(!q)
        cm_allocation_failure();
    return q;
}

static void *cm_xmalloc_array(size_t count, size_t element_size)
{
    return cm_xmalloc(cm_size_mul(count, element_size));
}

static void *cm_xrealloc_array(void *p, size_t count, size_t element_size)
{
    return cm_xrealloc(p, cm_size_mul(count, element_size));
}

static char *cm_xstrdup(const char *s)
{
    size_t n = s ? strlen(s) : 0;
    char *p = (char *)cm_xmalloc(cm_size_add(n, 1));

    if(n)
        memcpy(p, s, n);
    p[n] = 0;
    return p;
}

#define CM_TERMINAL_PATH_SLOTS 16
static char *g_terminal_path_slots[CM_TERMINAL_PATH_SLOTS];
static unsigned g_terminal_path_slot_index;
static int g_terminal_path_cleanup_registered;

static char *cm_path_normalize(const char *path);

static void cm_terminal_path_cleanup()
{
    unsigned i;

    for(i = 0; i < CM_TERMINAL_PATH_SLOTS; i++)
    {
        free(g_terminal_path_slots[i]);
        g_terminal_path_slots[i] = NULL;
    }
}

static const char *cm_terminal_path_view(const char *path)
{
    const unsigned char *p = (const unsigned char *)(path ? path : "");
    size_t needed = 0;

    unsigned slot;
    char *copy, *q;

    if(!g_terminal_path_cleanup_registered)
    {
        atexit(cm_terminal_path_cleanup);
        g_terminal_path_cleanup_registered = 1;
    }

    for(; *p; p++)
        if(*p == '\n' || *p == '\r')
            needed = cm_size_add(needed, 2);
        else if(*p < 32 || *p == 127)
            needed = cm_size_add(needed, 4);
        else
            needed = cm_size_add(needed, 1);

    slot = g_terminal_path_slot_index++ % CM_TERMINAL_PATH_SLOTS;
    free(g_terminal_path_slots[slot]);
    copy = (char *)cm_xmalloc(cm_size_add(needed, 1));
    q = copy;

    p = (const unsigned char *)(path ? path : "");
    for(; *p; p++)
        if(*p == '\\')
        {
            *q++ = '/';
        }
        else if(*p == '\n')
        {
            *q++ = '\\';
            *q++ = 'n';
        }
        else if(*p == '\r')
        {
            *q++ = '\\';
            *q++ = 'r';
        }
        else if(*p < 32 || *p == 127)
        {
            static const char hex[] = "0123456789ABCDEF";
            *q++ = '\\';
            *q++ = 'x';
            *q++ = hex[*p >> 4];
            *q++ = hex[*p & 15];
        }
        else
        {
            *q++ = (char)*p;
        }
    *q = 0;

    g_terminal_path_slots[slot] = copy;

    return copy;
}

static const char *cm_terminal_absolute_path_view(const char *path)
{
    char *absolute = cm_path_normalize(path);
    const char *view = cm_terminal_path_view(absolute);

    free(absolute);

    return view;
}

static char *cm_xstrndup(const char *s, size_t n)
{
    char *p = (char *)cm_xmalloc(cm_size_add(n, 1));

    memcpy(p, s, n);
    p[n] = 0;
    return p;
}

static void cm_buf_init(CmBuf *b)
{
    memset(b, 0, sizeof(*b));
}

static void cm_buf_reserve(CmBuf *b, size_t extra)
{
    size_t need = cm_size_add(cm_size_add(b->len, extra), 1);

    if(need <= b->cap)
        return;

    size_t cap = b->cap ? b->cap : 128;

    while(cap < need)
    {
        if(cap > SIZE_MAX / 2)
        {
            cap = need;
            break;
        }
        cap *= 2;
    }

    b->data = (char *)cm_xrealloc(b->data, cap);
    b->cap = cap;
}

static void cm_buf_append_n(CmBuf *b, const char *s, size_t n)
{
    cm_buf_reserve(b, n);
    memcpy(b->data + b->len, s, n);
    b->len += n;
    b->data[b->len] = 0;
}

static void cm_buf_append(CmBuf *b, const char *s)
{
    cm_buf_append_n(b, s, strlen(s));
}

static void cm_buf_putc(CmBuf *b, char c)
{
    cm_buf_reserve(b, 1);
    b->data[b->len++] = c;
    b->data[b->len] = 0;
}

static char *cm_buf_take(CmBuf *b)
{
    char *p;

    if(!b->data)
        return cm_xstrdup("");
    p = b->data;
    b->data = NULL;
    b->len = b->cap = 0;
    return p;
}

static void cm_buf_free(CmBuf *b)
{
    free(b->data);
    memset(b, 0, sizeof(*b));
}

static void cm_sv_push(CmStrVec *v, const char *s)
{
    if(v->n == v->cap)
    {
        size_t new_cap = v->cap ? cm_size_mul(v->cap, 2) : 16;

        v->v = (char **)cm_xrealloc_array(v->v, new_cap, sizeof(char *));
        v->cap = new_cap;
    }

    v->v[v->n++] = cm_xstrdup(s);
}

static int cm_sv_contains(const CmStrVec *v, const char *s)
{
    size_t i;

    for(i = 0; i < v->n; i++)
        if(strcmp(v->v[i], s) == 0)
            return 1;
    return 0;
}

static void cm_sv_free(CmStrVec *v)
{
    size_t i;

    for(i = 0; i < v->n; i++)
        free(v->v[i]);
    free(v->v);
    memset(v, 0, sizeof(*v));
}

static void cm_mv_push(CmManifestVec *v, const char *path, const char *algo)
{
    if(v->n == v->cap)
    {
        size_t new_cap = v->cap ? cm_size_mul(v->cap, 2) : 16;

        v->v = (CmManifest *)cm_xrealloc_array(v->v, new_cap, sizeof(CmManifest));
        v->cap = new_cap;
    }

    v->v[v->n].path = cm_xstrdup(path);
    v->v[v->n].algo = cm_xstrdup(algo);
    v->n++;
}

static void cm_mv_free(CmManifestVec *v)
{
    size_t i;

    for(i = 0; i < v->n; i++)
    {
        free(v->v[i].path);
        free(v->v[i].algo);
    }

    free(v->v);
    memset(v, 0, sizeof(*v));
}

static void cm_rv_push(CmRecordVec *v, const CmRecord *r)
{
    if(v->n == v->cap)
    {
        size_t new_cap = v->cap ? cm_size_mul(v->cap, 2) : 16;

        v->v = (CmRecord *)cm_xrealloc_array(v->v, new_cap, sizeof(CmRecord));
        v->cap = new_cap;
    }

    v->v[v->n].digest = cm_xstrdup(r->digest);
    v->v[v->n].name = cm_xstrdup(r->name);
    v->v[v->n].raw_name = cm_xstrdup(r->raw_name ? r->raw_name : r->name);
    v->v[v->n].escaped = r->escaped;
    v->v[v->n].line_no = r->line_no;
    v->n++;
}

static void cm_record_free(CmRecord *r)
{
    free(r->digest);
    free(r->name);
    free(r->raw_name);
    memset(r, 0, sizeof(*r));
}

static void cm_rv_free(CmRecordVec *v)
{
    size_t i;

    for(i = 0; i < v->n; i++)
        cm_record_free(&v->v[i]);
    free(v->v);
    memset(v, 0, sizeof(*v));
}

static void cm_count_add(CmCountMap *m, const char *key, int amount)
{
    size_t i;

    for(i = 0; i < m->n; i++)
        if(strcmp(m->v[i].key, key) == 0)
        {
            m->v[i].count += amount;
            return;
        }
    if(m->n == m->cap)
    {
        size_t new_cap = m->cap ? cm_size_mul(m->cap, 2) : 16;

        m->v = (CmCountEntry *)cm_xrealloc_array(m->v, new_cap, sizeof(CmCountEntry));
        m->cap = new_cap;
    }

    m->v[m->n].key = cm_xstrdup(key);
    m->v[m->n].count = amount;
    m->n++;
}

static void cm_count_inc(CmCountMap *m, const char *key)
{
    cm_count_add(m, key, 1);
}

static int cm_count_get(const CmCountMap *m, const char *key)
{
    size_t i;

    for(i = 0; i < m->n; i++)
        if(strcmp(m->v[i].key, key) == 0)
            return m->v[i].count;
    return 0;
}

/* Keep per-algorithm entry counters column-aligned with a minimum label width of five characters ("Total"). */
static size_t cm_entry_label_width(const CmStrVec *algorithms)
{
    size_t i, w = 5;

    for(i = 0; i < algorithms->n; i++)
    {
        size_t n = strlen(algorithms->v[i]);

        if(n > w)
            w = n;
    }

    return w;
}

static void cm_print_mode_entries(const CmStrVec *algorithms, const CmCountMap *counts, int total)
{
    size_t i, w = cm_entry_label_width(algorithms);

    printf("Entries:\n");
    for(i = 0; i < algorithms->n; i++)
        printf("  %-*s: %d\n", (int)w, algorithms->v[i], cm_count_get(counts, algorithms->v[i]));
    printf("  %-*s: %d\n\n", (int)w, "Total", total);
}

static void cm_count_free(CmCountMap *m)
{
    size_t i;

    for(i = 0; i < m->n; i++)
        free(m->v[i].key);
    free(m->v);
    memset(m, 0, sizeof(*m));
}

static void cm_pov_push(CmProviderOverrideVec *v, const char *algo, const char *provider)
{
    if(v->n == v->cap)
    {
        size_t new_cap = v->cap ? cm_size_mul(v->cap, 2) : 8;

        v->v = (CmProviderOverride *)cm_xrealloc_array(v->v, new_cap, sizeof(CmProviderOverride));
        v->cap = new_cap;
    }

    v->v[v->n].algo = cm_xstrdup(algo);
    v->v[v->n].provider = cm_xstrdup(provider);
    v->n++;
}

static void cm_pov_free(CmProviderOverrideVec *v)
{
    size_t i;

    for(i = 0; i < v->n; i++)
    {
        free(v->v[i].algo);
        free(v->v[i].provider);
    }

    free(v->v);
    memset(v, 0, sizeof(*v));
}

static void cm_pcv_push(CmProviderChoiceVec *v, const CmAlgorithmInfo *algo, CmProvider provider)
{
    if(v->n == v->cap)
    {
        size_t new_cap = v->cap ? cm_size_mul(v->cap, 2) : 16;

        v->v = (CmProviderChoice *)cm_xrealloc_array(v->v, new_cap, sizeof(CmProviderChoice));
        v->cap = new_cap;
    }

    v->v[v->n].algo = algo;
    v->v[v->n].provider = provider;
    v->n++;
}

static void cm_pcv_free(CmProviderChoiceVec *v)
{
    free(v->v);
    memset(v, 0, sizeof(*v));
}

static int cm_ascii_tolower(int c)
{
    return (c >= 'A' && c <= 'Z') ? c + ('a' - 'A') : c;
}

static int cm_ascii_equal_ci(const char *a, const char *b)
{
    while(*a && *b)
    {
        if(cm_ascii_tolower((unsigned char)*a) != cm_ascii_tolower((unsigned char)*b))
            return 0;
        a++;
        b++;
    }

    return *a == *b;
}

static void cm_ascii_lower_inplace(char *s)
{
    for(; *s; s++)
        *s = (char)cm_ascii_tolower((unsigned char)*s);
}

static char *cm_ascii_trim_dup(const char *s)
{
    const char *a = s, *b = s + strlen(s);

    while(a < b && strchr(" \t\r\n\v\f", *a))
        a++;
    while(b > a && strchr(" \t\r\n\v\f", b[-1]))
        b--;
    return cm_xstrndup(a, (size_t)(b - a));
}

static int cm_is_hex_string(const char *s)
{
    if(!s || !*s)
        return 0;
    for(; *s; s++)
        if(!isxdigit((unsigned char)*s))
            return 0;
    return 1;
}

static int cm_valid_transform_name(const char *s)
{
    const unsigned char *p = (const unsigned char *)s;

    if(!*p || !((*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9')))
        return 0;
    for(p++; *p; p++)
        if(!((*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') || *p == '.' || *p == '_' || *p == '+' || *p == '-'))
            return 0;

    return 1;
}

static const CmAlgorithmInfo *cm_find_algo(const char *name)
{
    size_t i;
    char *n = cm_ascii_trim_dup(name);

    cm_ascii_lower_inplace(n);
    if(strcmp(n, "sfv") == 0)
    {
        free(n);
        n = cm_xstrdup("crc32");
    }

    for(i = 0; i < CM_ARRAY_LEN(kAlgorithmInfo); i++)
        if(strcmp(n, kAlgorithmInfo[i].name) == 0)
        {
            free(n);
            return &kAlgorithmInfo[i];
        }
    free(n);

    return NULL;
}

static const char *cm_algo_ext(const char *algo)
{
    const CmAlgorithmInfo *a = cm_find_algo(algo);

    return a ? (a->extension ? a->extension : a->name) : algo;
}

static int cm_algo_builtin(const char *name)
{
    return cm_find_algo(name) != NULL;
}

static int cm_algo_crc(const char *name)
{
    return cm_ascii_equal_ci(name, "crc32") || cm_ascii_equal_ci(name, "crc32c") || cm_ascii_equal_ci(name, "sfv");
}

/* ----------------------------- platform paths ----------------------------- */

static void cm_split_path_segments(const char *path, CmStrVec *out);

#ifdef _WIN32
static wchar_t *cm_utf8_to_wide(const char *s)
{
    int n;
    wchar_t *w;

    if(!s)
        return NULL;
    n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s, -1, NULL, 0);
    if(n <= 0)
        return NULL;
    w = (wchar_t *)cm_xmalloc_array((size_t)n, sizeof(wchar_t));
    if(MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s, -1, w, n) <= 0)
    {
        free(w);
        return NULL;
    }

    return w;
}

static char *cm_wide_to_utf8(const wchar_t *w)
{
    int n;
    char *s;

    if(!w)
        return NULL;
    n = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, w, -1, NULL, 0, NULL, NULL);
    if(n <= 0)
        return NULL;
    s = (char *)cm_xmalloc((size_t)n);
    if(WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, w, -1, s, n, NULL, NULL) <= 0)
    {
        free(s);
        return NULL;
    }

    return s;
}

static void cm_set_errno_from_win32(DWORD error)
{
    switch(error)
    {
        case ERROR_FILE_NOT_FOUND:
        case ERROR_PATH_NOT_FOUND:
        case ERROR_INVALID_DRIVE:
            errno = ENOENT;
            break;
        case ERROR_ACCESS_DENIED:
        case ERROR_SHARING_VIOLATION:
        case ERROR_LOCK_VIOLATION:
            errno = EACCES;
            break;
        case ERROR_FILE_EXISTS:
        case ERROR_ALREADY_EXISTS:
            errno = EEXIST;
            break;
        case ERROR_DISK_FULL:
#ifdef ERROR_HANDLE_DISK_FULL
        case ERROR_HANDLE_DISK_FULL:
#endif
            errno = ENOSPC;
            break;
        case ERROR_NOT_ENOUGH_MEMORY:
        case ERROR_OUTOFMEMORY:
            errno = ENOMEM;
            break;
        case ERROR_INVALID_NAME:
        case ERROR_INVALID_PARAMETER:
            errno = EINVAL;
            break;
#ifdef ENOTEMPTY
        case ERROR_DIR_NOT_EMPTY:
            errno = ENOTEMPTY;
            break;
#endif
        default:
            errno = EIO;
            break;
    }
}

static FILE *cm_fopen(const char *path, const char *mode)
{
    wchar_t *p = cm_utf8_to_wide(path), *m = cm_utf8_to_wide(mode);
    FILE *f = NULL;

    if(p && m)
        f = _wfopen(p, m);
    free(p);
    free(m);

    return f;
}

static int cm_unlink(const char *path)
{
    wchar_t *w = cm_utf8_to_wide(path);
    int ok = w ? _wunlink(w) : -1;

    free(w);

    return ok;
}

static int cm_rename(const char *a, const char *b)
{
    wchar_t *wa = cm_utf8_to_wide(a), *wb = cm_utf8_to_wide(b);
    int ok = -1;

    if(wa && wb)
    {
        if(MoveFileExW(wa, wb, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
            ok = 0;
        else
            cm_set_errno_from_win32(GetLastError());
    }
    else
    {
        errno = EINVAL;
    }

    free(wa);
    free(wb);

    return ok;
}

static int cm_mkdir_one(const char *path)
{
    wchar_t *w = cm_utf8_to_wide(path);
    int ok = -1;

    if(w)
        if(CreateDirectoryW(w, NULL) || GetLastError() == ERROR_ALREADY_EXISTS)
            ok = 0;
    free(w);

    return ok;
}

static int cm_chmod_0644(const char *path)
{
    wchar_t *w = cm_utf8_to_wide(path);
    int ok = w ? _wchmod(w, _S_IREAD | _S_IWRITE) : -1;

    free(w);

    return ok;
}
#else
/*
 * Resolve a POSIX path one component at a time.  This avoids passing an
 * arbitrarily long full pathname to a single syscall and lets recursive scans
 * continue beyond PATH_MAX when the filesystem itself permits the directory
 * hierarchy.  The returned descriptor owns the parent directory of *leaf.
 */
static int cm_posix_parent_fd(const char *path, char **leaf)
{
    CmStrVec segments = {0};
    int fd, next;
    size_t i;

    if(!path || !*path || !leaf)
    {
        errno = EINVAL;
        return -1;
    }

    cm_split_path_segments(path, &segments);
    fd = open(path[0] == '/' ? "/" : ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if(fd < 0)
    {
        cm_sv_free(&segments);
        return -1;
    }

    if(segments.n == 0)
    {
        *leaf = cm_xstrdup(".");
        cm_sv_free(&segments);
        return fd;
    }

    for(i = 0; i + 1 < segments.n; i++)
    {
        next = openat(fd, segments.v[i], O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if(next < 0)
        {
            int saved_errno = errno;

            close(fd);
            cm_sv_free(&segments);
            errno = saved_errno;
            return -1;
        }
        close(fd);
        fd = next;
    }

    *leaf = cm_xstrdup(segments.v[segments.n - 1]);
    cm_sv_free(&segments);

    return fd;
}

static int cm_posix_open_path(const char *path, int flags, mode_t mode)
{
    char *leaf = NULL;
    int parent = cm_posix_parent_fd(path, &leaf), fd;

    if(parent < 0)
        return -1;
    fd = openat(parent, leaf, flags, mode);
    if(fd < 0)
    {
        int saved_errno = errno;

        free(leaf);
        close(parent);
        errno = saved_errno;
        return -1;
    }

    free(leaf);
    close(parent);

    return fd;
}

static FILE *cm_fopen(const char *path, const char *mode)
{
    int flags, fd;
    FILE *f;

    if(strcmp(mode, "rb") == 0)
        flags = O_RDONLY | O_CLOEXEC;
    else if(strcmp(mode, "wb") == 0)
        flags = O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC;
    else
        return fopen(path, mode);
    fd = cm_posix_open_path(path, flags, 0666);
    if(fd < 0)
        return NULL;
    f = fdopen(fd, mode);
    if(!f)
        close(fd);

    return f;
}

static int cm_unlink(const char *path)
{
    char *leaf = NULL;
    int parent = cm_posix_parent_fd(path, &leaf), rc;

    if(parent < 0)
        return -1;
    rc = unlinkat(parent, leaf, 0);
    free(leaf);
    close(parent);

    return rc;
}

static int cm_rename(const char *a, const char *b)
{
    char *aleaf = NULL, *bleaf = NULL;
    int aparent = cm_posix_parent_fd(a, &aleaf), bparent, rc;

    if(aparent < 0)
        return -1;
    bparent = cm_posix_parent_fd(b, &bleaf);
    if(bparent < 0)
    {
        free(aleaf);
        close(aparent);
        return -1;
    }

    rc = renameat(aparent, aleaf, bparent, bleaf);
    free(aleaf);
    free(bleaf);
    close(aparent);
    close(bparent);

    return rc;
}

static int cm_mkdir_one(const char *path)
{
    char *leaf = NULL;
    int parent = cm_posix_parent_fd(path, &leaf), rc;

    if(parent < 0)
        return -1;
    rc = mkdirat(parent, leaf, 0777);
    if(rc != 0 && errno == EEXIST)
        rc = 0;
    free(leaf);
    close(parent);

    return rc;
}

static int cm_chmod_0644(const char *path)
{
    char *leaf = NULL;
    int parent = cm_posix_parent_fd(path, &leaf), rc;

    if(parent < 0)
        return -1;
    rc = fchmodat(parent, leaf, 0644, 0);
    free(leaf);
    close(parent);

    return rc;
}
#endif

static char *cm_getcwd_utf8()
{
#ifdef _WIN32
    DWORD n = GetCurrentDirectoryW(0, NULL);
    wchar_t *w;
    char *s;

    if(!n)
        return cm_xstrdup(".");
    w = (wchar_t *)cm_xmalloc_array((size_t)n, sizeof(wchar_t));
    if(!GetCurrentDirectoryW(n, w))
    {
        free(w);
        return cm_xstrdup(".");
    }

    s = cm_wide_to_utf8(w);
    free(w);

    return s ? s : cm_xstrdup(".");
#else
    size_t n = 256;
    char *p;

    for(;;)
    {
        p = (char *)cm_xmalloc(n);
        if(getcwd(p, n))
            return p;
        free(p);
        if(errno != ERANGE)
            return cm_xstrdup(".");
        n = cm_size_mul(n, 2);
    }
#endif
}

static int cm_is_sep(char c)
{
#ifdef _WIN32
    return c == '/' || c == '\\';
#else
    return c == '/';
#endif
}

static int cm_path_is_abs(const char *p)
{
#ifdef _WIN32
    return (p && ((isalpha((unsigned char)p[0]) && p[1] == ':' && cm_is_sep(p[2])) || (cm_is_sep(p[0]) && cm_is_sep(p[1]))));
#else
    return p && p[0] == '/';
#endif
}

static char *cm_path_join(const char *a, const char *b)
{
    CmBuf out;
    size_t n;

    if(!a || !*a)
        return cm_xstrdup(b ? b : "");
    if(!b || !*b)
        return cm_xstrdup(a);
    if(cm_path_is_abs(b))
        return cm_xstrdup(b);
    cm_buf_init(&out);
    cm_buf_append(&out, a);
    n = out.len;
    if(n && !cm_is_sep(out.data[n - 1]))
        cm_buf_putc(&out, CM_SEP);
    cm_buf_append(&out, b);

    return cm_buf_take(&out);
}

static char *cm_path_dirname(const char *p)
{
    size_t n, last = (size_t)-1, i;

    if(!p || !*p)
        return cm_xstrdup(".");
    n = strlen(p);
    while(n > 1 && cm_is_sep(p[n - 1]))
        n--;
    for(i = 0; i < n; i++)
        if(cm_is_sep(p[i]))
            last = i;
    if(last == (size_t)-1)
        return cm_xstrdup(".");
#ifdef _WIN32
    if(last == 2 && isalpha((unsigned char)p[0]) && p[1] == ':')
        return cm_xstrndup(p, 3);
#endif
    if(last == 0)
        return cm_xstrndup(p, 1);

    return cm_xstrndup(p, last);
}

static const char *cm_path_basename_ptr(const char *p)
{
    const char *b = p, *q;

    if(!p)
        return "";
    for(q = p; *q; q++)
        if(cm_is_sep(*q))
            b = q + 1;
    return b;
}

static char *cm_path_basename(const char *p)
{
    return cm_xstrdup(cm_path_basename_ptr(p));
}

/* lexical absolute normalization; it does not resolve symlinks */
static char *cm_path_normalize(const char *path)
{
#ifdef _WIN32
    wchar_t *input, *full;
    DWORD needed, written;
    char *result, *p;
    const char *effective = (path && *path) ? path : ".";

    input = cm_utf8_to_wide(effective);
    if(!input)
        return cm_xstrdup(effective);
    needed = GetFullPathNameW(input, 0, NULL, NULL);
    if(!needed)
    {
        free(input);
        return cm_xstrdup(effective);
    }

    full = (wchar_t *)cm_xmalloc_array((size_t)needed, sizeof(wchar_t));
    written = GetFullPathNameW(input, needed, full, NULL);
    free(input);
    if(!written || written >= needed)
    {
        free(full);
        return cm_xstrdup(effective);
    }

    result = cm_wide_to_utf8(full);
    free(full);
    if(!result)
        return cm_xstrdup(effective);
    for(p = result; *p; ++p)
        if(*p == '/')
            *p = '\\';

    return result;
#else
    CmStrVec seg = {0, 0, 0};
    CmBuf out;
    char *input, *p, *tok;
    size_t i;
    int absolute = cm_path_is_abs(path);

    if(!path || !*path)
        return cm_xstrdup(".");
    if(!absolute)
    {
        char *cwd = cm_getcwd_utf8();

        input = cm_path_join(cwd, path);
        free(cwd);
    }
    else
    {
        input = cm_xstrdup(path);
    }
    p = input;
    while(*p && cm_is_sep(*p))
        p++;
    while(*p)
    {
        char *start = p;

        while(*p && !cm_is_sep(*p))
            p++;
        tok = cm_xstrndup(start, (size_t)(p - start));
        while(*p && cm_is_sep(*p))
            p++;
        if(strcmp(tok, ".") == 0 || !*tok)
        {
            free(tok);
            continue;
        }
        if(strcmp(tok, "..") == 0)
        {
            if(seg.n > 0)
                free(seg.v[--seg.n]);
            free(tok);
            continue;
        }
        cm_sv_push(&seg, tok);
        free(tok);
    }

    cm_buf_init(&out);
    cm_buf_putc(&out, '/');
    for(i = 0; i < seg.n; i++)
    {
        if(out.len && !cm_is_sep(out.data[out.len - 1]))
            cm_buf_putc(&out, CM_SEP);
        cm_buf_append(&out, seg.v[i]);
    }

    cm_sv_free(&seg);
    free(input);

    return cm_buf_take(&out);
#endif
}

/* Resolve an existing path through symlinks/reparse points for timestamp journaling. */
static char *cm_path_real_existing(const char *path)
{
#ifdef _WIN32
    typedef DWORD (WINAPI *CmGetFinalPathNameByHandleWFn)(HANDLE, LPWSTR, DWORD, DWORD);
    wchar_t *w = cm_utf8_to_wide(path);
    HANDLE h;
    HMODULE kernel;
    CmGetFinalPathNameByHandleWFn get_final;
    DWORD needed, written;
    wchar_t *buf;
    char *utf8, *result;

    if(!w)
        return cm_path_normalize(path);
    h = CreateFileW(w, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    free(w);
    if(h == INVALID_HANDLE_VALUE)
        return cm_path_normalize(path);
    kernel = GetModuleHandleW(L"kernel32.dll");
    get_final = kernel ? (CmGetFinalPathNameByHandleWFn)GetProcAddress(kernel, "GetFinalPathNameByHandleW") : NULL;
    if(!get_final)
    {
        CloseHandle(h);
        return cm_path_normalize(path);
    }

    needed = get_final(h, NULL, 0, 0);
    if(!needed)
    {
        CloseHandle(h);
        return cm_path_normalize(path);
    }

    buf = (wchar_t *)cm_xmalloc_array(cm_size_add((size_t)needed, 1U), sizeof(wchar_t));
    written = get_final(h, buf, needed + 1U, 0);
    CloseHandle(h);
    if(!written || written > needed)
    {
        free(buf);
        return cm_path_normalize(path);
    }

    buf[written] = L'\0';
    utf8 = cm_wide_to_utf8(buf);
    free(buf);
    if(!utf8)
        return cm_path_normalize(path);
    if(strncmp(utf8, "\\\\?\\UNC\\", 8) == 0)
    {
        size_t n = strlen(utf8 + 8);

        result = (char *)cm_xmalloc(cm_size_add(n, 3));
        result[0] = '\\';
        result[1] = '\\';
        memcpy(result + 2, utf8 + 8, n + 1);
        free(utf8);
        return result;
    }

    if(strncmp(utf8, "\\\\?\\", 4) == 0)
    {
        result = cm_xstrdup(utf8 + 4);
        free(utf8);
        return result;
    }

    return utf8;
#else
    char *resolved = realpath(path, NULL);

    if(resolved)
        return resolved;

    return cm_path_normalize(path);
#endif
}

static int cm_file_info(const char *path, int follow, CmFileInfo *out)
{
    memset(out, 0, sizeof(*out));
#ifdef _WIN32
    wchar_t *w = cm_utf8_to_wide(path);
    WIN32_FILE_ATTRIBUTE_DATA data;
    DWORD attrs;

    if(!w)
    {
        errno = EINVAL;
        return -1;
    }
    attrs = GetFileAttributesW(w);
    if(attrs == INVALID_FILE_ATTRIBUTES)
    {
        DWORD error = GetLastError();

        free(w);
        cm_set_errno_from_win32(error);
        return -1;
    }

    out->exists = 1;
    out->is_symlink = (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
    if(!follow && out->is_symlink)
    {
        free(w);
        return 0;
    }

    if(!GetFileAttributesExW(w, GetFileExInfoStandard, &data))
    {
        DWORD error = GetLastError();

        free(w);
        cm_set_errno_from_win32(error);
        return -1;
    }

    out->is_dir = (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    out->is_reg = !out->is_dir;
    out->size = ((unsigned long long)data.nFileSizeHigh << 32) | data.nFileSizeLow;
    {
        ULARGE_INTEGER u;

        u.LowPart = data.ftLastWriteTime.dwLowDateTime;
        u.HighPart = data.ftLastWriteTime.dwHighDateTime;
        out->mtime.sec = (long long)(u.QuadPart / 10000000ULL - 11644473600ULL);
        out->mtime.nsec = (long)((u.QuadPart % 10000000ULL) * 100);
        out->mtime.valid = 1;
    }

    /* Preserve the writable/read-only state as permission bits, not raw
     * FILE_ATTRIBUTE_* flags.  _wchmod() only uses the read/write permission
     * bits, so a normal writable file must carry _S_IWRITE here; storing
     * FILE_ATTRIBUTE_ARCHIVE (0x20), for example, would otherwise be
     * misread as a read-only mode later. */
    out->mode = _S_IREAD;
    if((data.dwFileAttributes & FILE_ATTRIBUTE_READONLY) == 0)
        out->mode |= _S_IWRITE;
    free(w);

    return 0;
#else
    char *leaf = NULL;
    struct stat st;
    int parent = cm_posix_parent_fd(path, &leaf), rc;

    if(parent < 0)
        return -1;
    rc = fstatat(parent, leaf, &st, follow ? 0 : AT_SYMLINK_NOFOLLOW);
    if(rc != 0)
    {
        int saved_errno = errno;

        free(leaf);
        close(parent);
        errno = saved_errno;
        return -1;
    }

    free(leaf);
    close(parent);
    out->exists = 1;
    out->is_reg = S_ISREG(st.st_mode);
    out->is_dir = S_ISDIR(st.st_mode);
    out->is_symlink = S_ISLNK(st.st_mode);
    out->size = (unsigned long long)st.st_size;
    out->mode = (unsigned long)st.st_mode;
    out->dev = st.st_dev;
    out->ino = st.st_ino;
#if defined(__APPLE__)
    out->mtime.sec = (long long)st.st_mtimespec.tv_sec;
    out->mtime.nsec = st.st_mtimespec.tv_nsec;
#else
    out->mtime.sec = (long long)st.st_mtim.tv_sec;
    out->mtime.nsec = st.st_mtim.tv_nsec;
#endif
    out->mtime.valid = 1;

    return 0;
#endif
}

static FILE *cm_progress_terminal_open()
{
    FILE *terminal;

#ifdef _WIN32
    {
        HANDLE handle;
        int descriptor;

        handle = CreateFileA("CONOUT$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        if(handle == INVALID_HANDLE_VALUE)
            return NULL;
        descriptor = _open_osfhandle((intptr_t)handle, _O_RDWR | _O_TEXT);
        if(descriptor < 0)
        {
            CloseHandle(handle);
            return NULL;
        }
        terminal = _fdopen(descriptor, "r+");
        if(!terminal)
        {
            _close(descriptor);
            return NULL;
        }
    }
    if(!_isatty(_fileno(terminal)))
    {
        fclose(terminal);
        terminal = NULL;
    }
#else
    {
        const char *term = getenv("TERM");
        int descriptor;

        if(term && strcmp(term, "dumb") == 0)
            return NULL;
        descriptor = open("/dev/tty", O_WRONLY | O_NONBLOCK);
        if(descriptor < 0)
            return NULL;
        terminal = fdopen(descriptor, "w");
        if(!terminal)
        {
            close(descriptor);
            return NULL;
        }
    }
    if(!isatty(fileno(terminal)))
    {
        fclose(terminal);
        terminal = NULL;
    }
#endif
    if(terminal)
        setvbuf(terminal, NULL, _IONBF, 0);

    return terminal;
}

static int cm_progress_write(FILE *terminal, const char *text)
{
    if(!terminal || !text)
        return 0;
    if(fputs(text, terminal) == EOF || fflush(terminal) != 0)
    {
        clearerr(terminal);
        return 0;
    }
    return 1;
}

static unsigned cm_progress_terminal_columns(FILE *terminal)
{
#ifdef _WIN32
    HANDLE handle;
    CONSOLE_SCREEN_BUFFER_INFO info;

    if(!terminal)
        return 0;
    handle = (HANDLE)_get_osfhandle(_fileno(terminal));
    if(handle == INVALID_HANDLE_VALUE || !GetConsoleScreenBufferInfo(handle, &info) || info.dwSize.X <= 1)
        return 0;
    if(info.srWindow.Right >= info.srWindow.Left)
    {
        unsigned window_width = (unsigned)(info.srWindow.Right - info.srWindow.Left + 1);

        if(window_width > 1 && window_width < (unsigned)info.dwSize.X)
            return window_width;
    }
    return (unsigned)info.dwSize.X;
#else
    struct winsize size;

    if(!terminal || ioctl(fileno(terminal), TIOCGWINSZ, &size) != 0 || size.ws_col <= 1)
        return 0;
    return (unsigned)size.ws_col;
#endif
}

static int cm_progress_is_mintty()
{
#ifndef _WIN32
    const char *term_program = getenv("TERM_PROGRAM");

    return term_program && strcmp(term_program, "mintty") == 0;
#else
    return 0;
#endif
}

static int cm_progress_set_line_rewrap(FILE *terminal, int enabled)
{
#ifndef _WIN32
    if(terminal && cm_progress_is_mintty())
        return cm_progress_write(terminal, enabled ? "\033[?7723h" : "\033[?7723l");
#else
    (void)terminal;
    (void)enabled;
#endif
    return 1;
}

static void cm_progress_disable(CmHashProgress *progress)
{
    if(!progress)
        return;
    if(progress->terminal)
        fclose(progress->terminal);
    progress->terminal = NULL;
    progress->active = 0;
    progress->line_length = 0;
}

static int cm_progress_clear_line(CmHashProgress *progress)
{
    if(!progress->terminal || progress->line_length == 0)
        return 1;
#ifdef _WIN32
    {
        HANDLE handle = (HANDLE)_get_osfhandle(_fileno(progress->terminal));
        CONSOLE_SCREEN_BUFFER_INFO info;

        if(handle == INVALID_HANDLE_VALUE || !GetConsoleScreenBufferInfo(handle, &info) || info.dwSize.X <= 0)
            return 0;
        {
            COORD start = { 0, info.dwCursorPosition.Y };
            DWORD written = 0;

            if(!FillConsoleOutputCharacterW(handle, L' ', (DWORD)info.dwSize.X, start, &written))
                return 0;
            if(!SetConsoleCursorPosition(handle, start))
                return 0;
        }
    }
#else
    if(!cm_progress_write(progress->terminal, "\r\033[2K"))
        return 0;
    if(!cm_progress_set_line_rewrap(progress->terminal, 1))
        return 0;
#endif
    progress->line_length = 0;
    return 1;
}

static unsigned long long cm_progress_now_ms()
{
#ifdef _WIN32
    return (unsigned long long)GetTickCount();
#elif defined(CLOCK_MONOTONIC)
    struct timespec ts;

    if(clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (unsigned long long)ts.tv_sec * 1000ULL + (unsigned long long)ts.tv_nsec / 1000000ULL;
#else
    clock_t value = clock();

    if(value == (clock_t)-1)
        return 0;
    return (unsigned long long)((double)value * 1000.0 / (double)CLOCKS_PER_SEC);
#endif
}

static void cm_progress_human_size(unsigned long long bytes, char *output, size_t output_size)
{
    const char *units[] = { "B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB" };
    double value = (double)bytes;
    size_t unit_index = 0;

    while(value >= 1024.0 && unit_index + 1 < CM_ARRAY_LEN(units))
    {
        value /= 1024.0;
        unit_index++;
    }
    if(unit_index == 0)
        snprintf(output, output_size, "%llu B", bytes);
    else
        snprintf(output, output_size, "%.2f %s", value, units[unit_index]);
}

static int cm_progress_file_size(FILE *file, unsigned long long *size)
{
    if(!file || !size)
        return 0;
#ifdef _WIN32
    {
        struct _stat64 st;

        if(_fstat64(_fileno(file), &st) != 0 || (st.st_mode & _S_IFMT) != _S_IFREG || st.st_size < 0)
            return 0;
        *size = (unsigned long long)st.st_size;
    }
#else
    {
        struct stat st;

        if(fstat(fileno(file), &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0)
            return 0;
        *size = (unsigned long long)st.st_size;
    }
#endif
    return 1;
}

static void cm_progress_render(CmHashProgress *progress)
{
    char line[192];
    char processed_size[64];
    char total_size[64];
    double percent;
    unsigned columns;
    size_t line_length, max_width;

    if(!progress->active || !progress->terminal || progress->disabled_after_resize)
        return;
    columns = cm_progress_terminal_columns(progress->terminal);
    if(progress->initial_columns == 0 && columns > 1)
    {
        progress->initial_columns = columns;
    }
    else if(progress->initial_columns > 0 && columns != progress->initial_columns)
    {
        if(!cm_progress_clear_line(progress))
        {
            cm_progress_disable(progress);
            return;
        }
        progress->disabled_after_resize = 1;
        progress->last_update_ms = cm_progress_now_ms();
        return;
    }
    if(progress->total == 0)
    {
        percent = 100.0;
    }
    else
    {
        percent = (double)progress->processed * 100.0 / (double)progress->total;
        if(percent > 100.0)
            percent = 100.0;
    }
    cm_progress_human_size(progress->processed, processed_size, sizeof(processed_size));
    cm_progress_human_size(progress->total, total_size, sizeof(total_size));
    snprintf(line, sizeof(line), "Hashing [%s]  %s/%s    %.2f%%", progress->algorithm, processed_size, total_size, percent);
    line_length = strlen(line);
    if(!cm_progress_clear_line(progress))
    {
        cm_progress_disable(progress);
        return;
    }
    if(columns <= 1)
    {
        progress->last_update_ms = cm_progress_now_ms();
        return;
    }
    max_width = (size_t)columns - 1;
    if(max_width < line_length)
    {
        progress->last_update_ms = cm_progress_now_ms();
        return;
    }
#ifndef _WIN32
    if(!cm_progress_write(progress->terminal, "\r\033[2K"))
    {
        cm_progress_disable(progress);
        return;
    }
    if(!cm_progress_set_line_rewrap(progress->terminal, 0))
    {
        cm_progress_disable(progress);
        return;
    }
#else
    if(!cm_progress_write(progress->terminal, "\r"))
    {
        cm_progress_disable(progress);
        return;
    }
#endif
    progress->line_length = line_length;
    if(!cm_progress_write(progress->terminal, line))
    {
        cm_progress_disable(progress);
        return;
    }
    progress->last_update_ms = cm_progress_now_ms();
}

#ifdef _WIN32
typedef struct
{
    HANDLE stop_event;
    HANDLE thread;
    volatile LONG processed_sequence;
    volatile LONG processed_low;
    volatile LONG processed_high;
    unsigned long long processed_value;
    unsigned long long total;
    const char *algorithm;
} CmWindowsProgress;

static volatile LONG g_progress_windows_disabled = 0;

static unsigned long long cm_progress_windows_processed_read(CmWindowsProgress *context)
{
    LONG sequence_before, sequence_after;
    DWORD low, high;

    for(;;)
    {
        sequence_before = InterlockedCompareExchange(&context->processed_sequence, 0, 0);
        if((sequence_before & 1L) != 0)
            continue;
        low = (DWORD)InterlockedCompareExchange(&context->processed_low, 0, 0);
        high = (DWORD)InterlockedCompareExchange(&context->processed_high, 0, 0);
        sequence_after = InterlockedCompareExchange(&context->processed_sequence, 0, 0);
        if(sequence_before == sequence_after && (sequence_after & 1L) == 0)
            return ((unsigned long long)high << 32) | (unsigned long long)low;
    }
}

static void cm_progress_windows_processed_add(CmWindowsProgress *context, size_t amount)
{
    DWORD low, high;

    if((unsigned long long)amount > ULLONG_MAX - context->processed_value)
        context->processed_value = ULLONG_MAX;
    else
        context->processed_value += (unsigned long long)amount;
    low = (DWORD)(context->processed_value & 0xffffffffULL);
    high = (DWORD)(context->processed_value >> 32);
    InterlockedIncrement(&context->processed_sequence);
    InterlockedExchange(&context->processed_low, (LONG)low);
    InterlockedExchange(&context->processed_high, (LONG)high);
    InterlockedIncrement(&context->processed_sequence);
}

static DWORD WINAPI cm_progress_windows_worker(LPVOID argument)
{
    CmWindowsProgress *context = (CmWindowsProgress *)argument;
    CmHashProgress display;
    DWORD wait_result;

    memset(&display, 0, sizeof(display));
    display.algorithm = context->algorithm;
    display.total = context->total;
    display.terminal = cm_progress_terminal_open();
    if(!display.terminal)
        return 0;
    display.active = 1;
    for(;;)
    {
        display.processed = cm_progress_windows_processed_read(context);
        cm_progress_render(&display);
        if(!display.active || !display.terminal)
            return 0;
        wait_result = WaitForSingleObject(context->stop_event, (DWORD)CM_PROGRESS_INTERVAL_MS);
        if(wait_result == WAIT_FAILED)
        {
            InterlockedExchange(&g_progress_windows_disabled, 1);
            break;
        }
        if(wait_result != WAIT_TIMEOUT)
            break;
    }
    if(display.active && display.terminal)
    {
        display.processed = cm_progress_windows_processed_read(context);
        cm_progress_render(&display);
        if(display.active && display.terminal)
        {
            if(cm_progress_clear_line(&display))
                cm_progress_write(display.terminal, "\r");
            fclose(display.terminal);
            display.terminal = NULL;
            display.active = 0;
        }
    }

    return 0;
}
#endif

static void cm_progress_begin(CmHashProgress *progress, FILE *file)
{
    if(!progress || !progress->requested || progress->active)
        return;
    if(!cm_progress_file_size(file, &progress->total))
        return;
#ifdef _WIN32
    {
        CmWindowsProgress *context;

        if(InterlockedCompareExchange(&g_progress_windows_disabled, 0, 0) != 0)
            return;
        context = (CmWindowsProgress *)calloc(1, sizeof(*context));
        if(!context)
            return;
        context->total = progress->total;
        context->algorithm = progress->algorithm;
        context->stop_event = CreateEventA(NULL, TRUE, FALSE, NULL);
        if(!context->stop_event)
        {
            free(context);
            return;
        }
        context->thread = CreateThread(NULL, 0, cm_progress_windows_worker, context, 0, NULL);
        if(!context->thread)
        {
            CloseHandle(context->stop_event);
            free(context);
            return;
        }
        progress->windows_context = context;
        progress->active = 1;
    }
#else
    progress->terminal = cm_progress_terminal_open();
    if(!progress->terminal)
        return;
    progress->active = 1;
    cm_progress_render(progress);
#endif
}

static void cm_progress_advance(CmHashProgress *progress, size_t amount)
{
#ifndef _WIN32
    unsigned long long now;
#endif

    if(!progress || !progress->active)
        return;
#ifdef _WIN32
    if(progress->windows_context)
    {
        CmWindowsProgress *context = (CmWindowsProgress *)progress->windows_context;

        cm_progress_windows_processed_add(context, amount);
    }
#else
    if((unsigned long long)amount > ULLONG_MAX - progress->processed)
        progress->processed = ULLONG_MAX;
    else
        progress->processed += (unsigned long long)amount;
    now = cm_progress_now_ms();
    if(now != 0 && (progress->last_update_ms == 0 || now - progress->last_update_ms >= CM_PROGRESS_INTERVAL_MS))
        cm_progress_render(progress);
#endif
}

static void cm_progress_end(CmHashProgress *progress)
{
    if(!progress || !progress->active)
        return;
#ifdef _WIN32
    if(progress->windows_context)
    {
        CmWindowsProgress *context = (CmWindowsProgress *)progress->windows_context;
        DWORD wait_result;

        if(!SetEvent(context->stop_event))
            InterlockedExchange(&g_progress_windows_disabled, 1);
        wait_result = WaitForSingleObject(context->thread, CM_PROGRESS_STOP_TIMEOUT_MS);
        if(wait_result == WAIT_FAILED)
            InterlockedExchange(&g_progress_windows_disabled, 1);
        if(wait_result == WAIT_OBJECT_0)
        {
            CloseHandle(context->thread);
            CloseHandle(context->stop_event);
            free(context);
        }
        else
        {
            InterlockedExchange(&g_progress_windows_disabled, 1);
            CloseHandle(context->thread);
        }
        progress->windows_context = NULL;
        progress->active = 0;
    }
#else
    if(!progress->terminal)
    {
        progress->active = 0;
        return;
    }
    cm_progress_render(progress);
    if(progress->active && progress->terminal)
    {
        if(!cm_progress_clear_line(progress))
        {
            cm_progress_disable(progress);
            return;
        }
        if(!cm_progress_write(progress->terminal, "\r"))
        {
            cm_progress_disable(progress);
            return;
        }
        fclose(progress->terminal);
        progress->terminal = NULL;
        progress->active = 0;
        progress->line_length = 0;
    }
#endif
}

static int cm_exists(const char *p)
{
    CmFileInfo s;

    return cm_file_info(p, 1, &s) == 0;
}

static int cm_is_file(const char *p)
{
    CmFileInfo s;

    return cm_file_info(p, 1, &s) == 0 && s.is_reg;
}

static int cm_is_dir(const char *p)
{
    CmFileInfo s;

    return cm_file_info(p, 1, &s) == 0 && s.is_dir;
}

static int cm_is_symlink(const char *p)
{
    CmFileInfo s;

    return cm_file_info(p, 0, &s) == 0 && s.is_symlink;
}

static int cm_is_readable_file(const char *p)
{
    if(!cm_is_file(p))
        return 0;
#ifdef _WIN32
    {
        wchar_t *w = cm_utf8_to_wide(p);
        int ok = w ? (_waccess(w, 4) == 0) : 0;

        free(w);
        return ok;
    }
#else
    char *leaf = NULL;
    int parent = cm_posix_parent_fd(p, &leaf), rc;

    if(parent < 0)
        return 0;
    rc = faccessat(parent, leaf, R_OK, 0);
    free(leaf);
    close(parent);

    return rc == 0;
#endif
}

static int cm_set_file_mode(const char *path, unsigned long mode)
{
#ifdef _WIN32
    wchar_t *w = cm_utf8_to_wide(path);
    int m = 0, rc;

    if(!w)
        return -1;
    if(mode & _S_IREAD)
        m |= _S_IREAD;
    if(mode & _S_IWRITE)
        m |= _S_IWRITE;
    if(!m)
        m = _S_IREAD;
    rc = _wchmod(w, m);
    free(w);

    return rc;
#else
    char *leaf = NULL;
    int parent = cm_posix_parent_fd(path, &leaf), rc;

    if(parent < 0)
        return -1;
    rc = fchmodat(parent, leaf, (mode_t)(mode & 07777), 0);
    free(leaf);
    close(parent);

    return rc;
#endif
}

static int cm_set_mtime(const char *path, CmTimestamp ts)
{
    if(!ts.valid)
        return -1;
#ifdef _WIN32
    wchar_t *w = cm_utf8_to_wide(path);
    HANDLE h;
    ULARGE_INTEGER u;
    FILETIME ft;
    int ok = -1;

    if(!w)
        return -1;
    h = CreateFileW(w, FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    free(w);
    if(h == INVALID_HANDLE_VALUE)
        return -1;
    u.QuadPart = ((unsigned long long)(ts.sec + 11644473600LL)) * 10000000ULL + (unsigned long long)(ts.nsec / 100);
    ft.dwLowDateTime = u.LowPart;
    ft.dwHighDateTime = u.HighPart;
    if(SetFileTime(h, NULL, NULL, &ft))
        ok = 0;
    CloseHandle(h);

    return ok;
#else
    char *leaf = NULL;
    struct timespec tv[2];
    int parent = cm_posix_parent_fd(path, &leaf), rc;

    if(parent < 0)
        return -1;
    tv[0].tv_sec = 0;
#ifdef UTIME_OMIT
    tv[0].tv_nsec = UTIME_OMIT;
#else
    {
        struct stat st;

        if(fstatat(parent, leaf, &st, 0) != 0)
        {
            free(leaf);
            close(parent);
            return -1;
        }
#if defined(__APPLE__)
        tv[0] = st.st_atimespec;
#else
        tv[0] = st.st_atim;
#endif
    }
#endif
    tv[1].tv_sec = (time_t)ts.sec;
    tv[1].tv_nsec = ts.nsec;
    rc = utimensat(parent, leaf, tv, 0);
    free(leaf);
    close(parent);

    return rc;
#endif
}

static int cm_path_mtime_matches(const char *path, CmTimestamp ts, int want_directory)
{
    CmFileInfo current;

    if(!ts.valid || cm_file_info(path, 0, &current) != 0 || !current.mtime.valid)
        return -1;
    if(want_directory ? !current.is_dir : !current.is_reg)
        return -1;
    return current.mtime.sec == ts.sec && current.mtime.nsec == ts.nsec;
}

static int cm_make_dirs(const char *path)
{
    char *n = cm_path_normalize(path), *p;
    size_t start = 0;

#ifdef _WIN32
    if(n[0] && n[1] && isalpha((unsigned char)n[0]) && n[1] == ':' && cm_is_sep(n[2]))
    {
        start = 3;
    }
    else if(cm_is_sep(n[0]) && cm_is_sep(n[1]))
    {
        const char *q = n + 2;

        while(*q && !cm_is_sep(*q))
            q++;
        if(*q)
            q++;
        while(*q && !cm_is_sep(*q))
            q++;
        start = *q ? (size_t)(q - n + 1) : strlen(n);
    }
    else
    {
        start = 1;
    }
#else
    start = 1;
#endif

    for(p = n + start; *p; p++)
        if(cm_is_sep(*p))
        {
            char save = *p;
            *p = 0;
            if(*n && !cm_is_dir(n) && cm_mkdir_one(n) != 0)
            {
                *p = save;
                free(n);
                return -1;
            }
            *p = save;
        }
    if(!cm_is_dir(n) && cm_mkdir_one(n) != 0)
    {
        free(n);
        return -1;
    }

    free(n);

    return 0;
}

static int cm_same_path_prefix(const char *root, const char *path)
{
    size_t n = strlen(root);

    if(strlen(path) < n)
        return 0;

#ifdef _WIN32
    size_t i;

    for(i = 0; i < n; i++)
        if(cm_ascii_tolower((unsigned char)root[i]) != cm_ascii_tolower((unsigned char)path[i]))
            return 0;
#else
    if(strncmp(root, path, n) != 0)
        return 0;
#endif
    if(path[n] == 0)
        return 1;

    return cm_is_sep(path[n]) || (n > 0 && cm_is_sep(root[n - 1]));
}

static void cm_split_path_segments(const char *path, CmStrVec *out)
{
    const char *p = path;

#ifdef _WIN32
    if(isalpha((unsigned char)p[0]) && p[1] == ':')
        p += 2;
#endif

    while(*p)
    {
        const char *start;
        char *segment;

        while(*p && cm_is_sep(*p))
            p++;
        if(!*p)
            break;
        start = p;
        while(*p && !cm_is_sep(*p))
            p++;
        segment = cm_xstrndup(start, (size_t)(p - start));
        cm_sv_push(out, segment);
        free(segment);
    }
}

static char *cm_relative_path(const char *from_dir, const char *target)
{
    char *a = cm_path_normalize(from_dir);
    char *b = cm_path_normalize(target);
    CmStrVec av = {0, 0, 0}, bv = {0, 0, 0};
    size_t i = 0, j;
    CmBuf out;

#ifdef _WIN32
    if(isalpha((unsigned char)a[0]) && a[1] == ':' &&
        isalpha((unsigned char)b[0]) && b[1] == ':' &&
        cm_ascii_tolower((unsigned char)a[0]) != cm_ascii_tolower((unsigned char)b[0]))
    {
        free(a);
        return b;
    }
#endif

    cm_split_path_segments(a, &av);
    cm_split_path_segments(b, &bv);
#ifdef _WIN32
    while(i < av.n && i < bv.n && cm_ascii_equal_ci(av.v[i], bv.v[i]))
        i++;
#else
    while(i < av.n && i < bv.n && strcmp(av.v[i], bv.v[i]) == 0)
        i++;
#endif

    cm_buf_init(&out);
    for(j = i; j < av.n; j++)
    {
        if(out.len)
            cm_buf_putc(&out, CM_SEP);
        cm_buf_append(&out, "..");
    }

    for(j = i; j < bv.n; j++)
    {
        if(out.len)
            cm_buf_putc(&out, CM_SEP);
        cm_buf_append(&out, bv.v[j]);
    }

    if(!out.len)
        cm_buf_append(&out, ".");
    cm_sv_free(&av);
    cm_sv_free(&bv);
    free(a);
    free(b);

    return cm_buf_take(&out);
}

/* ----------------------------- directory scan ----------------------------- */

typedef int (*CmScanCallback)(const char *path, void *user);

static int cm_list_directory(const char *dir, CmStrVec *names)
{
#ifdef _WIN32
    char *pattern = cm_path_join(dir, "*");
    wchar_t *w = cm_utf8_to_wide(pattern);

    WIN32_FIND_DATAW fd;
    HANDLE h;
    DWORD error = ERROR_NO_MORE_FILES;

    free(pattern);
    if(!w)
    {
        errno = EINVAL;
        return -1;
    }
    h = FindFirstFileW(w, &fd);
    if(h == INVALID_HANDLE_VALUE)
        error = GetLastError();
    free(w);
    if(h == INVALID_HANDLE_VALUE)
    {
        cm_set_errno_from_win32(error);
        return -1;
    }
    do
    {
        char *s;

        if(g_interrupted)
            break;
        if(wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0)
            continue;
        s = cm_wide_to_utf8(fd.cFileName);
        if(s)
        {
            cm_sv_push(names, s);
            free(s);
        }
    }
    while(FindNextFileW(h, &fd));
    if(!g_interrupted)
        error = GetLastError();
    FindClose(h);
    if(g_interrupted)
        return -1;
    if(error != ERROR_NO_MORE_FILES)
    {
        cm_set_errno_from_win32(error);
        return -1;
    }

    return 0;
#else
    int fd = cm_posix_open_path(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
    DIR *d;
    struct dirent *e;

    if(fd < 0)
        return -1;
    d = fdopendir(fd);
    if(!d)
    {
        close(fd);
        return -1;
    }

    errno = 0;
    while((e = readdir(d)) != NULL)
    {
        if(g_interrupted)
        {
            closedir(d);
            return -1;
        }
        if(strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        cm_sv_push(names, e->d_name);
    }

    if(errno)
    {
        closedir(d);
        return -1;
    }

    closedir(d);

    return 0;
#endif
}

static int cm_byte_compare_qsort(const void *aa, const void *bb)
{
    const char *a = *(char *const *)aa, *b = *(char *const *)bb;

    return strcmp(a, b);
}

static int cm_natural_compare_str(const char *a, const char *b)
{
    const unsigned char *x = (const unsigned char *)a;
    const unsigned char *y = (const unsigned char *)b;

    while(*x || *y)
    {
        const unsigned char *xe, *ye;
        int xd, yd;
        size_t xl, yl, common;
        int c;

        if(!*x)
            return -1;
        if(!*y)
            return 1;
        xd = isdigit(*x) != 0;
        yd = isdigit(*y) != 0;
        xe = x;
        ye = y;
        while(*xe && ((isdigit(*xe) != 0) == xd))
            xe++;
        while(*ye && ((isdigit(*ye) != 0) == yd))
            ye++;
        xl = (size_t)(xe - x);
        yl = (size_t)(ye - y);
        if(xd && yd)
        {
            const unsigned char *xs = x, *ys = y;
            size_t xnl, ynl;

            while(xs < xe && *xs == '0')
                xs++;
            while(ys < ye && *ys == '0')
                ys++;
            xnl = (size_t)(xe - xs);
            ynl = (size_t)(ye - ys);
            if(xnl == 0)
            {
                xs = (const unsigned char *)"0";
                xnl = 1;
            }
            if(ynl == 0)
            {
                ys = (const unsigned char *)"0";
                ynl = 1;
            }
            if(xnl != ynl)
                return xnl < ynl ? -1 : 1;
            c = memcmp(xs, ys, xnl);
            if(c)
                return c < 0 ? -1 : 1;
            if(xl != yl)
                return xl < yl ? -1 : 1;
        }
        else if(!xd && !yd)
        {
            common = xl < yl ? xl : yl;
            c = memcmp(x, y, common);
            if(c)
                return c < 0 ? -1 : 1;
            if(xl != yl)
                return xl < yl ? -1 : 1;
        }
        else
        {
            return *x < *y ? -1 : 1;
        }
        x = xe;
        y = ye;
    }

    return 0;
}

static int cm_natural_qsort(const void *aa, const void *bb)
{
    return cm_natural_compare_str(*(char *const *)aa, *(char *const *)bb);
}

typedef struct
{
    char *path;
    CmStrVec names;
    size_t index;
} CmWalkFrame;

/*
 * Traverse with an explicit heap-backed frame stack rather than C recursion.
 * Together with descriptor-relative POSIX I/O, this keeps recursive discovery
 * independent of both the process call-stack depth and PATH_MAX-sized syscalls.
 */
static int cm_walk(const char *path, int recursive, int natural, CmScanCallback cb, void *user)
{
    CmFileInfo root_info;
    CmWalkFrame *frames = NULL;
    size_t frame_count = 0, frame_capacity = 0;
    int result = 0;

    if(g_interrupted)
        return -1;
    if(cm_file_info(path, 1, &root_info) != 0)
    {
        fprintf(stderr, "Error: %s: cannot inspect filesystem entry: %s\n", cm_terminal_path_view(path), strerror(errno));
        g_scan_errors++;
        return -1;
    }

    if(root_info.is_reg)
        return cb(path, user);
    if(!root_info.is_dir)
        return 0;

    frame_capacity = 16;
    frames = (CmWalkFrame *)cm_xmalloc_array(frame_capacity, sizeof(CmWalkFrame));
    memset(frames, 0, cm_size_mul(frame_capacity, sizeof(CmWalkFrame)));
    frames[0].path = cm_xstrdup(path);
    if(cm_list_directory(path, &frames[0].names) != 0)
    {
        if(!g_interrupted)
        {
            fprintf(stderr, "Error: %s: cannot scan directory: %s\n", cm_terminal_path_view(path), strerror(errno));
            g_scan_errors++;
        }
        free(frames[0].path);
        cm_sv_free(&frames[0].names);
        free(frames);
        return -1;
    }

    if(frames[0].names.n > 1)
        qsort(frames[0].names.v, frames[0].names.n, sizeof(char *), natural ? cm_natural_qsort : cm_byte_compare_qsort);
    frame_count = 1;

    while(frame_count > 0)
    {
        CmWalkFrame *frame = &frames[frame_count - 1];
        char *child;
        CmFileInfo lst, fst;
        int callback_result;

        if(g_interrupted)
        {
            result = -1;
            break;
        }
        if(frame->index >= frame->names.n)
        {
            free(frame->path);
            cm_sv_free(&frame->names);
            memset(frame, 0, sizeof(*frame));
            frame_count--;
            continue;
        }

        child = cm_path_join(frame->path, frame->names.v[frame->index++]);
        if(cm_file_info(child, 0, &lst) != 0)
        {
            fprintf(stderr, "Error: %s: cannot inspect filesystem entry: %s\n", cm_terminal_path_view(child), strerror(errno));
            g_scan_errors++;
            free(child);
            continue;
        }
        if(lst.is_symlink)
        {
            if(cm_file_info(child, 1, &fst) == 0 && fst.is_reg)
            {
                callback_result = cb(child, user);
                if(callback_result != 0)
                {
                    free(child);
                    result = callback_result;
                    break;
                }
            }
            free(child);
            continue;
        }
        if(lst.is_reg)
        {
            callback_result = cb(child, user);
            free(child);
            if(callback_result != 0)
            {
                result = callback_result;
                break;
            }
            continue;
        }
        if(lst.is_dir && recursive)
        {
            CmWalkFrame next_frame;

            memset(&next_frame, 0, sizeof(next_frame));
            next_frame.path = child;
            if(cm_list_directory(child, &next_frame.names) != 0)
            {
                if(g_interrupted)
                {
                    free(next_frame.path);
                    cm_sv_free(&next_frame.names);
                    result = -1;
                    break;
                }
                fprintf(stderr, "Error: %s: cannot scan directory: %s\n", cm_terminal_path_view(child), strerror(errno));
                g_scan_errors++;
                free(next_frame.path);
                cm_sv_free(&next_frame.names);
                continue;
            }
            if(next_frame.names.n > 1)
                qsort(next_frame.names.v, next_frame.names.n, sizeof(char *), natural ? cm_natural_qsort : cm_byte_compare_qsort);
            if(frame_count == frame_capacity)
            {
                frame_capacity = cm_size_mul(frame_capacity, 2);
                frames = (CmWalkFrame *)cm_xrealloc_array(frames, frame_capacity, sizeof(CmWalkFrame));
            }
            frames[frame_count++] = next_frame;
            continue;
        }
        free(child);
    }

    while(frame_count > 0)
    {
        frame_count--;
        free(frames[frame_count].path);
        cm_sv_free(&frames[frame_count].names);
    }

    free(frames);

    return result;
}

/* ------------------------------- filtering -------------------------------- */

static int cm_ascii_fold_char(int c, int insensitive)
{
    if(!insensitive)
        return c;
    return cm_ascii_tolower(c);
}

static int cm_class_named(const char *name, size_t n, unsigned char c, int insensitive)
{
    if(n == 5 && memcmp(name, "alnum", 5) == 0)
        return (isalnum(c) && c < 128);
    if(n == 5 && memcmp(name, "alpha", 5) == 0)
        return (isalpha(c) && c < 128);
    if(n == 5 && memcmp(name, "blank", 5) == 0)
        return c == ' ' || c == '\t';
    if(n == 5 && memcmp(name, "cntrl", 5) == 0)
        return c <= 0x1f || c == 0x7f;
    if(n == 5 && memcmp(name, "digit", 5) == 0)
        return c >= '0' && c <= '9';
    if(n == 5 && memcmp(name, "graph", 5) == 0)
        return c >= 0x21 && c <= 0x7e;
    if(n == 5 && memcmp(name, "lower", 5) == 0)
        return insensitive ? (isalpha(c) && c < 128) : (c >= 'a' && c <= 'z');
    if(n == 5 && memcmp(name, "print", 5) == 0)
        return c >= 0x20 && c <= 0x7e;
    if(n == 5 && memcmp(name, "punct", 5) == 0)
        return (c >= 0x21 && c <= 0x2f) || (c >= 0x3a && c <= 0x40) || (c >= 0x5b && c <= 0x60) || (c >= 0x7b && c <= 0x7e);
    if(n == 5 && memcmp(name, "space", 5) == 0)
        return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\v' || c == '\f';
    if(n == 5 && memcmp(name, "upper", 5) == 0)
        return insensitive ? (isalpha(c) && c < 128) : (c >= 'A' && c <= 'Z');
    if(n == 6 && memcmp(name, "xdigit", 6) == 0)
        return isxdigit(c) != 0;

    return -1;
}

static int cm_glob_class_match(const char *p, size_t *used, unsigned char ch, int insensitive)
{
    size_t i = 1;
    int negate = 0, matched = 0, closed = 0;
    unsigned char c = (unsigned char)cm_ascii_fold_char(ch, insensitive);

    if(p[i] == '!' || p[i] == '^')
    {
        negate = 1;
        i++;
    }

    if(p[i] == ']')
    {
        if(c == ']')
            matched = 1;
        i++;
    }
    while(p[i])
    {
        if(p[i] == ']')
        {
            closed = 1;
            i++;
            break;
        }
        if(p[i] == '[' && p[i + 1] == ':')
        {
            const char *end = strstr(p + i + 2, ":]");

            if(end)
            {
                int r = cm_class_named(p + i + 2, (size_t)(end - (p + i + 2)), ch, insensitive);

                if(r == 1)
                    matched = 1;
                if(r >= 0)
                {
                    i = (size_t)(end - p) + 2;
                    continue;
                }
            }
        }
        if(p[i] == '[' && (p[i + 1] == '=' || p[i + 1] == '.'))
        {
            char mark = p[i + 1];
            const char *end = p + i + 2;

            while(*end && !(end[0] == mark && end[1] == ']'))
                end++;
            if(*end && end == p + i + 3)
            {
                unsigned char q = (unsigned char)cm_ascii_fold_char((unsigned char)p[i + 2], insensitive);

                if(c == q)
                    matched = 1;
                i = (size_t)(end - p) + 2;
                continue;
            }
        }
        {
            unsigned char first;

            if(p[i] == '\\' && p[i + 1])
            {
                i++;
                first = (unsigned char)p[i++];
            }
            else
            {
                first = (unsigned char)p[i++];
            }
            first = (unsigned char)cm_ascii_fold_char(first, insensitive);
            if(p[i] == '-' && p[i + 1] && p[i + 1] != ']')
            {
                unsigned char last;

                i++;
                if(p[i] == '\\' && p[i + 1])
                {
                    i++;
                    last = (unsigned char)p[i++];
                }
                else
                {
                    last = (unsigned char)p[i++];
                }
                last = (unsigned char)cm_ascii_fold_char(last, insensitive);
                if(c >= first && c <= last)
                    matched = 1;
            }
            else if(c == first)
            {
                matched = 1;
            }
        }
    }

    if(!closed)
    {
        *used = 1;
        return c == (unsigned char)'[';
    }

    *used = i;

    return negate ? !matched : matched;
}

static int cm_glob_match_here(const char *p, const unsigned char *s, int insensitive)
{
    while(*p)
    {
        if(*p == '*')
        {
            while(*p == '*')
                p++;
            if(!*p)
                return 1;
            do
                if(cm_glob_match_here(p, s, insensitive))
                    return 1;
            while(*s++);
            return 0;
        }
        if(!*s)
            return 0;
        if(*p == '?')
        {
            p++;
            s++;
            continue;
        }
        if(*p == '\\')
        {
            p++;
            if(!*p)
            {
                if(*s != '\\')
                    return 0;
                s++;
                break;
            }
            if(cm_ascii_fold_char((unsigned char)*p, insensitive) != cm_ascii_fold_char(*s, insensitive))
                return 0;
            p++;
            s++;
            continue;
        }
        if(*p == '[')
        {
            size_t used = 0;

            if(!cm_glob_class_match(p, &used, *s, insensitive))
                return 0;
            p += used;
            s++;
            continue;
        }
        if(cm_ascii_fold_char((unsigned char)*p, insensitive) != cm_ascii_fold_char(*s, insensitive))
            return 0;
        p++;
        s++;
    }

    return *s == 0;
}

static int cm_filter_match(const char *path, const char *pattern, const char *case_mode)
{
    return cm_glob_match_here(pattern, (const unsigned char *)cm_path_basename_ptr(path), cm_ascii_equal_ci(case_mode, "insensitive"));
}

/* ----------------------------- manifest syntax ---------------------------- */

static char *cm_decode_escaped_filename(const char *s)
{
    CmBuf b;
    size_t i;

    cm_buf_init(&b);
    for(i = 0; s[i]; i++)
    {
        if(s[i] != '\\')
        {
            cm_buf_putc(&b, s[i]);
            continue;
        }
        i++;
        if(!s[i])
        {
            cm_buf_free(&b);
            return NULL;
        }
        if(s[i] == '\\')
        {
            cm_buf_putc(&b, '\\');
        }
        else if(s[i] == 'n')
        {
            cm_buf_putc(&b, '\n');
        }
        else if(s[i] == 'r')
        {
            cm_buf_putc(&b, '\r');
        }
        else
        {
            cm_buf_free(&b);
            return NULL;
        }
    }

    return cm_buf_take(&b);
}

static char *cm_encode_filename(const char *s, int *escaped)
{
    CmBuf b;
    const unsigned char *p = (const unsigned char *)s;
    int e = 0;

    cm_buf_init(&b);
    for(; *p; p++)
        if(*p == '\\')
        {
            cm_buf_append(&b, "\\\\");
            e = 1;
        }
        else if(*p == '\n')
        {
            cm_buf_append(&b, "\\n");
            e = 1;
        }
        else if(*p == '\r')
        {
            cm_buf_append(&b, "\\r");
            e = 1;
        }
        else
        {
            cm_buf_putc(&b, (char)*p);
        }
    if(escaped)
        *escaped = e;

    return cm_buf_take(&b);
}

/* Parse records without normalizing filename text so transform modes can preserve exact manifest spelling. */
static int cm_parse_manifest_line(const char *algo, const char *raw, CmRecord *out)
{
    const CmAlgorithmInfo *ai = cm_find_algo(algo);
    const char *p = raw;
    int escaped = 0;
    size_t len = strlen(raw);
    char *digest = NULL, *rawname = NULL, *name = NULL;

    memset(out, 0, sizeof(*out));
    if(len == 0)
        return 0;
    if(p[0] == '\\')
    {
        escaped = 1;
        p++;
    }
    else if(p[0] == '#' || p[0] == ';')
    {
        return 0;
    }
    if(ai && ai->style == CM_FILENAME_FIRST)
    {
        size_t n = strlen(p), hex_end = n, hex_start, ws_start;

        if(!n)
            return 0;
        hex_start = hex_end;
        while(hex_start > 0 && isxdigit((unsigned char)p[hex_start - 1]))
            hex_start--;
        if(hex_start == hex_end || hex_start == 0)
            return 0;
        ws_start = hex_start;
        while(ws_start > 0 && (p[ws_start - 1] == ' ' || p[ws_start - 1] == '\t'))
            ws_start--;
        if(ws_start == hex_start || ws_start == 0)
            return 0;
        digest = cm_xstrndup(p + hex_start, hex_end - hex_start);
        rawname = cm_xstrndup(p, ws_start);
    }
    else
    {
        size_t h = 0, plen = strlen(p), dlen = 0, di;
        const char *delims[] = {"  ", " *", "\t*", " ", "\t"};

        while(h < plen && isxdigit((unsigned char)p[h]))
            h++;
        if(h == 0)
            return 0;
        for(di = 0; di < CM_ARRAY_LEN(delims); di++)
        {
            size_t dl = strlen(delims[di]);
            /* Require a non-empty filename; this mirrors regex backtracking. */
            if(h + dl < plen && memcmp(p + h, delims[di], dl) == 0)
            {
                dlen = dl;
                break;
            }
        }
        if(!dlen)
            return 0;
        digest = cm_xstrndup(p, h);
        rawname = cm_xstrdup(p + h + dlen);
    }

    if(!cm_is_hex_string(digest) || !rawname || !*rawname)
    {
        free(digest);
        free(rawname);
        return 0;
    }

    name = escaped ? cm_decode_escaped_filename(rawname) : cm_xstrdup(rawname);
    if(!name)
    {
        free(digest);
        free(rawname);
        return 0;
    }

    out->digest = digest;
    out->name = name;
    out->raw_name = rawname;
    out->escaped = escaped;

    return 1;
}

static char *cm_format_record(const char *algo, const char *digest, const char *filename, const char *delimiter)
{
    const CmAlgorithmInfo *ai = cm_find_algo(algo);
    int escaped = 0;
    char *enc = cm_encode_filename(filename, &escaped);
    CmBuf b;

    cm_buf_init(&b);
    if(ai && ai->style == CM_FILENAME_FIRST && (filename[0] == '#' || filename[0] == ';'))
        escaped = 1;
    if(escaped)
        cm_buf_putc(&b, '\\');
    if(ai && ai->style == CM_FILENAME_FIRST)
    {
        cm_buf_append(&b, enc);
        cm_buf_putc(&b, ' ');
        cm_buf_append(&b, digest);
    }
    else
    {
        cm_buf_append(&b, digest);
        cm_buf_append(&b, delimiter ? delimiter : "  ");
        cm_buf_append(&b, enc);
    }

    free(enc);

    return cm_buf_take(&b);
}

static char *cm_format_record_preserving_name(const char *algo, const char *digest, const char *rawname, const char *delimiter, int escaped)
{
    const CmAlgorithmInfo *ai = cm_find_algo(algo);
    CmBuf b;

    cm_buf_init(&b);
    if(escaped)
        cm_buf_putc(&b, '\\');
    if(ai && ai->style == CM_FILENAME_FIRST)
    {
        cm_buf_append(&b, rawname);
        cm_buf_putc(&b, ' ');
        cm_buf_append(&b, digest);
    }
    else
    {
        cm_buf_append(&b, digest);
        cm_buf_append(&b, delimiter ? delimiter : "  ");
        cm_buf_append(&b, rawname);
    }

    return cm_buf_take(&b);
}

static int cm_read_lines(const char *path, CmStrVec *lines, int *has_nul)
{
    FILE *f = cm_fopen(path, "rb");
    CmBuf line;
    int c, line_has_nul = 0;

    if(has_nul)
        *has_nul = 0;
    if(!f)
        return -1;
    cm_buf_init(&line);
    while((c = fgetc(f)) != EOF)
    {
        if(g_interrupted)
        {
            cm_buf_free(&line);
            fclose(f);
            return -1;
        }
        if(c == 0)
        {
            if(has_nul)
                *has_nul = 1;
            line_has_nul = 1;
            continue;
        }
        if(c == '\n' || c == '\r')
        {
            if(c == '\r')
            {
                int n = fgetc(f);

                if(n != EOF && n != '\n')
                    ungetc(n, f);
            }
            /* A NUL-containing logical line is never a manifest record. */
            cm_sv_push(lines, line_has_nul ? "\x01" : (line.data ? line.data : ""));
            line.len = 0;
            if(line.data)
                line.data[0] = 0;
            line_has_nul = 0;
        }
        else
        {
            cm_buf_putc(&line, (char)c);
        }
    }

    if(ferror(f))
    {
        cm_buf_free(&line);
        fclose(f);
        return -1;
    }

    if(line.len || line_has_nul)
        cm_sv_push(lines, line_has_nul ? "\x01" : line.data);
    cm_buf_free(&line);
    fclose(f);

    return 0;
}

static const char *cm_newline_bytes(const char *mode)
{
    if(cm_ascii_equal_ci(mode, "unix") || cm_ascii_equal_ci(mode, "lf"))
        return "\n";
    if(cm_ascii_equal_ci(mode, "windows") || cm_ascii_equal_ci(mode, "crlf"))
        return "\r\n";
    if(cm_ascii_equal_ci(mode, "classic-mac") || cm_ascii_equal_ci(mode, "cr"))
        return "\r";
#ifdef _WIN32
    return "\r\n";
#else
    return "\n";
#endif
}

/* ---------------------------- path text modes ----------------------------- */

static const char *cm_system_path_mode()
{
    return CM_SEP == '\\' ? "backslash" : "slash";
}

static const char *cm_detect_path_mode(const char *s)
{
    const char *a = strchr(s, '/'), *b = strchr(s, '\\');

    if(!a && !b)
        return "slash";
    if(!a)
        return "backslash";
    if(!b)
        return "slash";

    return b < a ? "backslash" : "slash";
}

static const char *cm_effective_path_mode(const char *mode, const char *source)
{
    if(cm_ascii_equal_ci(mode, "default"))
        return cm_detect_path_mode(source ? source : "");
    if(cm_ascii_equal_ci(mode, "system"))
        return cm_system_path_mode();
    return mode;
}

static char *cm_manifest_path_to_native(const char *value, const char *mode, int derive_slash)
{
    const char *eff;
    char *r = cm_xstrdup(value), *p;

    if(derive_slash && cm_ascii_equal_ci(mode, "slash"))
    {
        for(p = r; *p; p++)
            if(*p == '/' || *p == '\\')
                *p = CM_SEP;
        return r;
    }

    eff = cm_effective_path_mode(mode, value);
    if(cm_ascii_equal_ci(eff, "slash") && CM_SEP != '/')
        for(p = r; *p; p++)
            if(*p == '/')
                *p = CM_SEP;
    if(cm_ascii_equal_ci(eff, "backslash") && CM_SEP != '\\')
        for(p = r; *p; p++)
            if(*p == '\\')
                *p = CM_SEP;

    return r;
}

static char cm_output_sep(const char *mode, const char *source)
{
    return cm_ascii_equal_ci(cm_effective_path_mode(mode, source ? source : ""), "backslash") ? '\\' : '/';
}

static char *cm_render_native_path(const char *path, const char *mode, const char *source)
{
    char sep = cm_output_sep(mode, source), *r = cm_xstrdup(path), *p;

    if(sep != CM_SEP)
        for(p = r; *p; p++)
            if(*p == CM_SEP)
                *p = sep;
    return r;
}

static char *cm_path_for_manifest_output(const char *native, const char *mode, const char *source)
{
    if(!native)
        return NULL;
#ifndef _WIN32
    if(cm_ascii_equal_ci(cm_effective_path_mode(mode, source ? source : ""), "backslash") && strchr(native, '\\'))
        return NULL;
#endif
    return cm_render_native_path(native, mode, source);
}

static char *cm_entry_target(const char *manifest, const char *entry, const char *mode, int allow_alternate, int derive_slash)
{
    char *mdir = cm_path_dirname(manifest), *native, *joined, *primary;

    if(cm_ascii_equal_ci(mode, "default"))
    {
        char *lit = cm_path_is_abs(entry) ? cm_path_normalize(entry) : NULL;

        if(!lit)
        {
            joined = cm_path_join(mdir, entry);
            lit = cm_path_normalize(joined);
            free(joined);
        }
        if(cm_exists(lit))
        {
            free(mdir);
            return lit;
        }
        free(lit);
    }

    native = cm_manifest_path_to_native(entry, mode, derive_slash);
    if(cm_path_is_abs(native))
    {
        primary = cm_path_normalize(native);
    }
    else
    {
        joined = cm_path_join(mdir, native);
        primary = cm_path_normalize(joined);
        free(joined);
    }
#ifndef _WIN32
    if(allow_alternate && cm_ascii_equal_ci(mode, "default") && !cm_exists(primary) && strchr(entry, '\\'))
    {
        char *alt = cm_xstrdup(entry), *p;

        for(p = alt; *p; p++)
            if(*p == '\\')
                *p = '/';
        joined = cm_path_join(mdir, alt);
        {
            char *candidate = cm_path_normalize(joined);

            if(cm_exists(candidate))
            {
                free(primary);
                primary = candidate;
            }
            else
            {
                free(candidate);
            }
        }
        free(joined);
        free(alt);
    }
#else
    if(allow_alternate && cm_ascii_equal_ci(mode, "default") && !cm_exists(primary) && strchr(entry, '/'))
    {
        char *alt = cm_xstrdup(entry), *p;

        for(p = alt; *p; p++)
            if(*p == '/')
                *p = '\\';
        joined = cm_path_join(mdir, alt);
        {
            char *candidate = cm_path_normalize(joined);

            if(cm_exists(candidate))
            {
                free(primary);
                primary = candidate;
            }
            else
            {
                free(candidate);
            }
        }
        free(joined);
        free(alt);
    }
#endif
    free(native);
    free(mdir);

    return primary;
}

/* ------------------------- selectors and providers ------------------------ */

static int cm_parse_selector(const char *value, int transform, int split, CmStrVec *out)
{
    char *work = cm_ascii_trim_dup(value), *p, *start;

    if(!*work)
    {
        free(work);
        return 0;
    }

    cm_ascii_lower_inplace(work);
    if(strcmp(work, "all") == 0)
    {
        size_t i;

        if(split)
        {
            free(work);
            return 0;
        }
        for(i = 0; i < CM_ARRAY_LEN(kAlgorithmInfo); i++)
            cm_sv_push(out, kAlgorithmInfo[i].name);
        free(work);
        return 1;
    }

    p = work;
    while(1)
    {
        char save;

        start = p;
        while(*p && *p != ',')
            p++;
        save = *p;
        *p = 0;
        {
            char *item = cm_ascii_trim_dup(start);

            if(strcmp(item, "sfv") == 0)
            {
                free(item);
                item = cm_xstrdup("crc32");
            }
            if(!*item || strcmp(item, "all") == 0 || (transform ? !cm_valid_transform_name(item) : !cm_algo_builtin(item)))
            {
                free(item);
                free(work);
                cm_sv_free(out);
                return 0;
            }
            if(!cm_sv_contains(out, item))
                cm_sv_push(out, item);
            free(item);
        }
        if(!save)
            break;
        p++;
    }

    free(work);
    if(split && out->n != 1)
    {
        cm_sv_free(out);
        return 0;
    }

    return out->n > 0;
}

static CmProvider cm_provider_from_name(const char *s, int *ok)
{
    char *n = cm_ascii_trim_dup(s);

    cm_ascii_lower_inplace(n);
    *ok = 1;
    if(strcmp(n, "auto") == 0)
    {
        free(n);
        return CM_PROVIDER_AUTO;
    }

    if(strcmp(n, "openssl") == 0)
    {
        free(n);
        return CM_PROVIDER_OPENSSL;
    }

    if(strcmp(n, "libgcrypt") == 0 || strcmp(n, "gcrypt") == 0)
    {
        free(n);
        return CM_PROVIDER_GCRYPT;
    }

    if(strcmp(n, "librhash") == 0 || strcmp(n, "rhash") == 0)
    {
        free(n);
        return CM_PROVIDER_RHASH;
    }

    *ok = 0;
    free(n);

    return CM_PROVIDER_AUTO;
}

static const char *cm_provider_name(CmProvider p)
{
    switch(p)
    {
    case CM_PROVIDER_OPENSSL:
        return "OpenSSL";
    case CM_PROVIDER_GCRYPT:
        return "Libgcrypt";
    case CM_PROVIDER_RHASH:
        return "LibRHash";
    default:
        return "Auto";
    }
}

static int cm_provider_declared_for_algorithm(const CmAlgorithmInfo *a, CmProvider p)
{
    const char *name = NULL;

    if(!a)
        return 0;
    if(p == CM_PROVIDER_OPENSSL)
        name = a->openssl_name;
    else if(p == CM_PROVIDER_GCRYPT)
        name = a->gcrypt_name;
    else if(p == CM_PROVIDER_RHASH)
        name = a->rhash_name;
    else
        return 0;
    /* NULL means derive the provider name dynamically; an empty string means
     * the provider is intentionally unsupported for this algorithm. */

    return name == NULL || name[0] != 0;
}

static int cm_parse_tools(const char *value, const CmStrVec *selected, CmProviderOverrideVec *out)
{
    char *work, *p, *start;

    if(!value)
        return 1;
    work = cm_ascii_trim_dup(value);
    if(!*work)
    {
        free(work);
        return 0;
    }

    p = work;
    for(;;)
    {
        char save, *colon, *a, *pr;
        size_t i;
        int ok, found = 0;

        start = p;
        while(*p && *p != ',')
            p++;
        save = *p;
        *p = 0;
        colon = strchr(start, ':');
        if(!colon)
        {
            free(work);
            return 0;
        }
        *colon = 0;
        a = cm_ascii_trim_dup(start);
        pr = cm_ascii_trim_dup(colon + 1);
        cm_ascii_lower_inplace(a);
        cm_ascii_lower_inplace(pr);
        if(strcmp(a, "sfv") == 0)
        {
            free(a);
            a = cm_xstrdup("crc32");
        }
        for(i = 0; i < selected->n; i++)
            if(strcmp(selected->v[i], a) == 0)
            {
                found = 1;
                break;
            }
        if(!found)
        {
            free(a);
            free(pr);
            free(work);
            return 0;
        }
        {
            CmProvider provider = cm_provider_from_name(pr, &ok);
            const CmAlgorithmInfo *info = cm_find_algo(a);

            if(!ok || provider == CM_PROVIDER_AUTO || !cm_provider_declared_for_algorithm(info, provider))
            {
                free(a);
                free(pr);
                free(work);
                return 0;
            }
        }
        for(i = 0; i < out->n; i++)
            if(strcmp(out->v[i].algo, a) == 0)
            {
                free(a);
                free(pr);
                free(work);
                return 0;
            }
        cm_pov_push(out, a, pr);
        free(a);
        free(pr);
        if(!save)
            break;
        p++;
    }

    free(work);

    return 1;
}

static const char *cm_provider_override_for(const CmProviderOverrideVec *v, const char *algo)
{
    size_t i;

    for(i = 0; i < v->n; i++)
        if(strcmp(v->v[i].algo, algo) == 0)
            return v->v[i].provider;
    return NULL;
}

static const char *cm_provider_algo_name(const CmAlgorithmInfo *a, CmProvider p, char *buf, size_t cap)
{
    const char *configured = NULL;
    size_t i;

    if(p == CM_PROVIDER_OPENSSL)
        configured = a->openssl_name;
    else if(p == CM_PROVIDER_GCRYPT)
        configured = a->gcrypt_name;
    else if(p == CM_PROVIDER_RHASH)
        configured = a->rhash_name;
    if(configured && configured[0] == 0)
        return NULL;
    if(configured)
        return configured;
    snprintf(buf, cap, "%s", a->name);
    if(p == CM_PROVIDER_GCRYPT)
        for(i = 0; buf[i]; i++)
            buf[i] = (char)toupper((unsigned char)buf[i]);

    return buf;
}

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
static int g_openssl_provider_init = 0;
static OSSL_PROVIDER *g_ossl_default = NULL, *g_ossl_legacy = NULL;

static void cm_openssl_init()
{
    if(!g_openssl_provider_init)
    {
        g_ossl_default = OSSL_PROVIDER_load(NULL, "default");
        g_ossl_legacy = OSSL_PROVIDER_load(NULL, "legacy");
        g_openssl_provider_init = 1;
    }
}
#else
static void cm_openssl_init()
{
    OpenSSL_add_all_digests();
}
#endif

static int cm_hash_openssl(const char *path, const CmAlgorithmInfo *a, CmHashProgress *progress, char **out)
{
    char namebuf[64];
    const char *name = cm_provider_algo_name(a, CM_PROVIDER_OPENSSL, namebuf, sizeof(namebuf));
    FILE *f;
    EVP_MD_CTX *ctx;
    unsigned char buffer[CM_HASH_CHUNK];
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;
    size_t n;
    int ok = 1;
    const EVP_MD *md = NULL;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    EVP_MD *fetched = NULL;
#endif

    if(!name)
        return 0;
    cm_openssl_init();
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    fetched = EVP_MD_fetch(NULL, name, NULL);
    md = fetched;
#else
    md = EVP_get_digestbyname(name);
#endif
    if(!md)
        return 0;
    f = cm_fopen(path, "rb");
    if(!f)
    {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        EVP_MD_free(fetched);
#endif
        return -1;
    }
    cm_progress_begin(progress, f);

    ctx = EVP_MD_CTX_new();
    if(!ctx)
    {
        fclose(f);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        EVP_MD_free(fetched);
#endif
        return -1;
    }

    if(EVP_DigestInit_ex(ctx, md, NULL) != 1)
        ok = 0;
    while(ok && (n = fread(buffer, 1, sizeof(buffer), f)) > 0)
    {
        if(g_interrupted)
        {
            ok = 0;
            break;
        }
        if(EVP_DigestUpdate(ctx, buffer, n) != 1)
            ok = 0;
        else
            cm_progress_advance(progress, n);
    }

    if(ferror(f))
        ok = 0;
    if(ok && EVP_DigestFinal_ex(ctx, digest, &dlen) != 1)
        ok = 0;
    EVP_MD_CTX_free(ctx);
    fclose(f);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    EVP_MD_free(fetched);
#endif

    if(!ok)
        return -1;
    {
        size_t i;
        char *hex = (char *)cm_xmalloc(cm_size_add(cm_size_mul((size_t)dlen, 2), 1));
        const char *digits = a->digest_case == CM_UPPERCASE ? "0123456789ABCDEF" : "0123456789abcdef";

        for(i = 0; i < dlen; i++)
        {
            hex[i * 2] = digits[digest[i] >> 4];
            hex[i * 2 + 1] = digits[digest[i] & 15];
        }
        hex[dlen * 2] = 0;
        *out = hex;
    }

    return 1;
}

static int cm_hash_gcrypt(const char *path, const CmAlgorithmInfo *a, CmHashProgress *progress, char **out)
{
    char namebuf[64];
    const char *name = cm_provider_algo_name(a, CM_PROVIDER_GCRYPT, namebuf, sizeof(namebuf));
    int id;
    gcry_md_hd_t ctx = NULL;
    FILE *f;
    unsigned char buffer[CM_HASH_CHUNK];
    size_t n;
    const unsigned char *raw;
    unsigned int dlen;
    int ok = 1;

    if(!name)
        return 0;
    if(!gcry_check_version(NULL))
        return 0;
    id = gcry_md_map_name(name);
    if(id == 0 || (dlen = gcry_md_get_algo_dlen(id)) == 0)
        return 0;
    if(gcry_md_open(&ctx, id, 0) != 0 || !ctx)
        return -1;
    f = cm_fopen(path, "rb");
    if(!f)
    {
        gcry_md_close(ctx);
        return -1;
    }
    cm_progress_begin(progress, f);
    while((n = fread(buffer, 1, sizeof(buffer), f)) > 0)
    {
        if(g_interrupted)
        {
            ok = 0;
            break;
        }
        gcry_md_write(ctx, buffer, n);
        cm_progress_advance(progress, n);
    }

    if(ferror(f))
        ok = 0;
    if(ok)
        gcry_md_final(ctx);
    raw = ok ? gcry_md_read(ctx, id) : NULL;
    if(ok && !raw)
        ok = 0;
    if(ok)
    {
        size_t i;
        char *hex = (char *)cm_xmalloc(cm_size_add(cm_size_mul((size_t)dlen, 2), 1));
        const char *digits = a->digest_case == CM_UPPERCASE ? "0123456789ABCDEF" : "0123456789abcdef";

        for(i = 0; i < dlen; i++)
        {
            hex[i * 2] = digits[raw[i] >> 4];
            hex[i * 2 + 1] = digits[raw[i] & 15];
        }
        hex[dlen * 2] = 0;
        *out = hex;
    }

    fclose(f);
    gcry_md_close(ctx);

    return ok ? 1 : -1;
}

static void cm_rhash_key(const char *s, char *out, size_t cap)
{
    size_t n = 0;

    for(; *s && n + 1 < cap; s++)
    {
        char c = (char)cm_ascii_tolower((unsigned char)*s);

        if(c == '-' || c == '_' || c == ' ' || c == '.')
            continue;
        out[n++] = c;
    }

    out[n] = 0;
}

static unsigned cm_rhash_id(const CmAlgorithmInfo *a)
{
    char namebuf[64], want[64];
    const char *name = cm_provider_algo_name(a, CM_PROVIDER_RHASH, namebuf, sizeof(namebuf));

    if(!name)
        return 0;
    rhash_library_init();
    cm_rhash_key(name, want, sizeof(want));
#ifdef RMSG_GET_ALL_ALGORITHMS
    {
        size_t count = rhash_get_all_algorithms(0, NULL), i, actual;
        unsigned *ids;

        if(!count || count > 4096)
            return 0;
        ids = (unsigned *)cm_xmalloc_array(count, sizeof(unsigned));
        actual = rhash_get_all_algorithms(count, ids);
        if(actual == (size_t)-1 || actual > count)
        {
            free(ids);
            return 0;
        }
        for(i = 0; i < actual; i++)
        {
            const char *rn = rhash_get_name(ids[i]);
            char key[64];

            if(!rn)
                continue;
            cm_rhash_key(rn, key, sizeof(key));
            if(strcmp(key, want) == 0)
            {
                unsigned id = ids[i];

                free(ids);
                return id;
            }
        }
        free(ids);
    }
#else
    {
        int bit;

        for(bit = 0; bit < 31; bit++)
        {
            unsigned id = (1U << bit);
            const char *rn = rhash_get_name(id);
            char key[64];

            if(!rn)
                continue;
            cm_rhash_key(rn, key, sizeof(key));
            if(strcmp(key, want) == 0)
                return id;
        }
    }
#endif
    return 0;
}

static int cm_hash_rhash(const char *path, const CmAlgorithmInfo *a, CmHashProgress *progress, char **out)
{
    unsigned id = cm_rhash_id(a);
    rhash ctx;
    FILE *f;
    unsigned char buffer[CM_HASH_CHUNK];
    size_t n;
    int ok = 1;
    char text[256];
    size_t printed;

    if(!id)
        return 0;
    rhash_library_init();
    ctx = rhash_init(id);
    if(!ctx)
        return -1;
    f = cm_fopen(path, "rb");
    if(!f)
    {
        rhash_free(ctx);
        return -1;
    }
    cm_progress_begin(progress, f);
    while((n = fread(buffer, 1, sizeof(buffer), f)) > 0)
    {
        if(g_interrupted)
        {
            ok = 0;
            break;
        }
        if(rhash_update(ctx, buffer, n) != 0)
        {
            ok = 0;
            break;
        }
        cm_progress_advance(progress, n);
    }

    if(ferror(f))
        ok = 0;
    if(ok && rhash_final(ctx, NULL) != 0)
        ok = 0;
    memset(text, 0, sizeof(text));
    printed = ok ? rhash_print(text, ctx, id, RHPR_HEX | (a->digest_case == CM_UPPERCASE ? RHPR_UPPERCASE : 0)) : 0;
    rhash_free(ctx);
    fclose(f);
    if(!ok || !printed)
        return -1;
    *out = cm_xstrndup(text, printed);

    return 1;
}

static int cm_hash_with_provider(const char *path, const CmAlgorithmInfo *a, CmProvider p, char **out, int show_progress)
{
    CmHashProgress progress;
    int rc;

    memset(&progress, 0, sizeof(progress));
    progress.requested = show_progress;
    progress.algorithm = a->name;
    if(p == CM_PROVIDER_OPENSSL)
        rc = cm_hash_openssl(path, a, &progress, out);
    else if(p == CM_PROVIDER_GCRYPT)
        rc = cm_hash_gcrypt(path, a, &progress, out);
    else if(p == CM_PROVIDER_RHASH)
        rc = cm_hash_rhash(path, a, &progress, out);
    else
        rc = 0;
    cm_progress_end(&progress);

    return rc;
}

static int cm_reserve_exclusive(const char *path);
static void cm_random_hex(char out[9]);
static void cm_registry_remove(CmStrVec *v, const char *path);

static int cm_provider_supports(const CmAlgorithmInfo *a, CmProvider p)
{
    char *digest = NULL;
    char tmpname[CM_PATH_MAX];
    int rc = 0, attempt;

    for(attempt = 0; attempt < 100; ++attempt)
    {
        char hex[9];

        cm_random_hex(hex);
#ifdef _WIN32
        wchar_t wbase[MAX_PATH];
        char *base;
        DWORD wn = GetTempPathW((DWORD)CM_ARRAY_LEN(wbase), wbase);

        if(!wn || wn >= CM_ARRAY_LEN(wbase))
            return 0;
        base = cm_wide_to_utf8(wbase);
        if(!base)
            return 0;
        snprintf(tmpname, sizeof(tmpname), "%scm-probe-%lu-%s.tmp", base, (unsigned long)GetCurrentProcessId(), hex);
        free(base);
#else
        snprintf(tmpname, sizeof(tmpname), "/tmp/.checksum-manifest-c-probe-%ld-%s", (long)getpid(), hex);
#endif

        if(cm_reserve_exclusive(tmpname) == 0)
        {
            cm_sv_push(&g_temp_paths, tmpname);
            rc = cm_hash_with_provider(tmpname, a, p, &digest, 0);
            free(digest);
            cm_unlink(tmpname);
            cm_registry_remove(&g_temp_paths, tmpname);
            return rc == 1;
        }
    }

    return 0;
}

static CmProvider cm_pick_provider(const CmAlgorithmInfo *a, const char *forced, int *ok)
{
    CmProvider order[] = {CM_PROVIDER_OPENSSL, CM_PROVIDER_GCRYPT, CM_PROVIDER_RHASH};
    size_t i;

    *ok = 0;
    if(forced)
    {
        int valid;
        CmProvider p = cm_provider_from_name(forced, &valid);

        if(!valid || p == CM_PROVIDER_AUTO)
            return CM_PROVIDER_AUTO;
        if(cm_provider_supports(a, p))
        {
            *ok = 1;
            return p;
        }
        return p;
    }

    for(i = 0; i < CM_ARRAY_LEN(order); i++)
        if(cm_provider_supports(a, order[i]))
        {
            *ok = 1;
            return order[i];
        }

    return CM_PROVIDER_AUTO;
}

/* Resolve and probe each algorithm once; execution then uses the locked provider choice for deterministic behavior. */
static int cm_prepare_providers(const CmStrVec *algos, const CmProviderOverrideVec *forced, CmProviderChoiceVec *out)
{
    size_t i;

    for(i = 0; i < algos->n; i++)
    {
        const CmAlgorithmInfo *a = cm_find_algo(algos->v[i]);
        const char *f = cm_provider_override_for(forced, algos->v[i]);
        int ok;
        CmProvider p;

        if(!a)
        {
            fprintf(stderr, "Error: unsupported hash algorithm: %s\n", algos->v[i]);
            return 0;
        }
        p = cm_pick_provider(a, f, &ok);
        if(!ok)
        {
            if(f)
                fprintf(stderr, "Error: pinned checksum provider is unavailable for %s: %s.\n", algos->v[i], f);
            else
                fprintf(stderr, "Error: no supported checksum provider available for: %s\n", algos->v[i]);
            return 0;
        }
        cm_pcv_push(out, a, p);
    }

    return 1;
}

static CmProvider cm_choice_for(const CmProviderChoiceVec *v, const char *algo)
{
    size_t i;

    for(i = 0; i < v->n; i++)
        if(strcmp(v->v[i].algo->name, algo) == 0)
            return v->v[i].provider;
    return CM_PROVIDER_AUTO;
}

/* ------------------------------- help text -------------------------------- */

static char *cm_program_display_name(const char *argv0)
{
    const char *base = cm_path_basename_ptr((argv0 && *argv0) ? argv0 : "checksum-manifest");
    size_t n = strlen(base);

#ifdef _WIN32
    if(n > 4 && base[n - 4] == '.' &&
        cm_ascii_tolower((unsigned char)base[n - 3]) == 'e' &&
        cm_ascii_tolower((unsigned char)base[n - 2]) == 'x' &&
        cm_ascii_tolower((unsigned char)base[n - 1]) == 'e')
        n -= 4;
#endif

    if(n == 0)
        return cm_xstrdup("checksum-manifest");

    return cm_xstrndup(base, n);
}

static void cm_print_help(const char *argv0)
{
    char *program = cm_program_display_name(argv0);
    size_t i;

    printf("Checksum Manifest Utility\n\n");
    printf("Usage:\n");
    printf("  %s check ALGORITHMS [OPTIONS] PATH_OR_CHECKSUM_FILE [CHECKSUM_FILE ...]\n", program);
    printf("  %s c ALGORITHMS [OPTIONS] PATH_OR_CHECKSUM_FILE [CHECKSUM_FILE ...]\n", program);
    printf("  %s hash ALGORITHMS [OPTIONS] PATH\n", program);
    printf("  %s h ALGORITHMS [OPTIONS] PATH\n", program);
    printf("  %s generate ALGORITHMS [OPTIONS] PATH\n", program);
    printf("  %s g ALGORITHMS [OPTIONS] PATH\n", program);
    printf("  %s derive ALGORITHMS --from SOURCE_ALGORITHMS [OPTIONS] PATH\n", program);
    printf("  %s d ALGORITHMS --from SOURCE_ALGORITHMS [OPTIONS] PATH\n", program);
    printf("  %s format ALGORITHMS [OPTIONS] PATH\n", program);
    printf("  %s f ALGORITHMS [OPTIONS] PATH\n", program);
    printf("  %s join ALGORITHMS [OPTIONS] PATH\n", program);
    printf("  %s j ALGORITHMS [OPTIONS] PATH\n", program);
    printf("  %s split ALGORITHM [OPTIONS] CHECKSUM_FILE\n", program);
    printf("  %s s ALGORITHM [OPTIONS] CHECKSUM_FILE\n", program);
    printf("  %s remove ALGORITHMS [OPTIONS] PATH\n", program);
    printf("  %s r ALGORITHMS [OPTIONS] PATH\n", program);
    printf("  %s (-h | --help | -v | --version)\n\n", program);

    printf("Modes:\n");
    printf("  check, c       Verify entries from selected checksum manifests.\n");
    printf("  hash, h        Calculate checksums and write hash output to stdout or one file.\n");
    printf("  generate, g    Generate checksum manifests for files.\n");
    printf("  derive, d      Create missing target manifests; compare entry paths in existing targets.\n");
    printf("  format, f      Rewrite manifest delimiter, newline, and path formatting.\n");
    printf("  join, j        Join selected checksum manifests into combined manifests.\n");
    printf("  split, s       Split one combined manifest into per-entry checksum files.\n");
    printf("  remove, r      Delete selected checksum manifest files after three confirmations.\n\n");

    printf("Selectors:\n");
    printf("  Names are case-insensitive. sfv is a reserved alias for crc32.\n");
    printf("  all is standalone and cannot be combined with comma-separated names.\n");
    printf("  In check/hash/generate/derive target selection, all expands to every built-in\n");
    printf("  hash algorithm. In format/join/remove and derive --from, it expands to the\n");
    printf("  same built-in extension list; split rejects all.\n");
    printf("  check/hash/generate/derive target selectors require built-in hash algorithms.\n");
    printf("  format/join/remove/split and derive --from also accept custom extension\n");
    printf("  names matching [A-Za-z0-9][A-Za-z0-9._+-]*. Duplicate normalized names\n");
    printf("  are ignored.\n\n");

    printf("Options:\n");
    printf("  -r, --recursive              Recurse for check/hash/generate/derive/format/join/remove.\n");
    printf("                               Invalid with split.\n");
    printf("  -o, --output PATH            check: report file. hash: one output file instead of stdout.\n");
    printf("                               generate: output root in separate\n");
    printf("                               layout or output file/directory in single layout.\n");
    printf("                               derive: output root directory. join: output file for\n");
    printf("                               one algorithm or directory for multiple algorithms.\n");
    printf("                               split: output root directory. Invalid with format/remove.\n");
    printf("                               Existing check/hash -o/generate/join/split outputs are preserved\n");
    printf("                               by collision-safe names.\n");
    printf("  -F, --from ALGORITHMS        derive only and required there. Select reference-manifest\n");
    printf("                               extensions.\n");
    printf("  -d, --delimiter VALUE        Non-CRC output must be exactly two spaces or \" *\". CRC\n");
    printf("                               accepts this option but always writes its filename-first\n");
    printf("                               single-space format. Input entry recognition is independent\n");
    printf("                               of this option. Invalid with remove.\n");
    printf("  -n, --newline MODE           unix|lf, windows|crlf, classic-mac|cr, or system.\n");
    printf("                               Case-insensitive. Default: unix. Invalid with remove.\n");
    printf("  -s, --path-separator MODE    slash, backslash, default, or system. Case-insensitive.\n");
    printf("                               Default: slash. In format, default preserves separators\n");
    printf("                               while slash/backslash/system normalize both separator\n");
    printf("                               characters textually. In check/derive/join/split the mode\n");
    printf("                               controls manifest-path interpretation; hash/generate control\n");
    printf("                               output. Invalid with remove.\n");
    printf("  -t, --tools SPEC             check/hash/generate/derive only. Pin native providers with\n");
    printf("                               ALGO:openssl|libgcrypt|librhash[,ALGO:PROVIDER...].\n");
    printf("                               Provider aliases: gcrypt and rhash. Pinned algorithms do\n");
    printf("                               not fall back; unlisted algorithms use automatic provider\n");
    printf("                               selection.\n");
    printf("  -f, --filter PATTERN         generate/hash only. Portable shell-style basename filter.\n");
    printf("                               Default: *.\n");
    printf("  -C, --filter-case MODE       generate/hash only: sensitive or insensitive. Requires explicit\n");
    printf("                               --filter. Insensitive matching folds ASCII only; [:upper:]\n");
    printf("                               and [:lower:] both act as [:alpha:]. Default: sensitive.\n");
    printf("  -D, --digest-only            hash only. Omit filenames and manifest record formatting.\n");
    printf("                               With multiple algorithms, keep aligned [algorithm] tags.\n");
    printf("  -l, --layout MODE            generate only: separate or single. Default: separate.\n");
    printf("  -N, --natural-sort           hash/generate/join/derive. generate requires --layout single.\n");
    printf("                               join sorts discovery; derive sorts valid reference entries.\n");
    printf("                               Mutually exclusive with -L.\n");
    printf("  -L, --lexicographic-sort     hash/generate/join/derive. generate requires --layout single.\n");
    printf("                               Bytewise order. Mutually exclusive with -N.\n");
    printf("  -T, --update-timestamp       derive/format/remove only. Disable their best-effort mtime\n");
    printf("                               preservation and leave timestamp updates to normal filesystem\n");
    printf("                               behavior.\n");
    printf("  -b, --backup                 format only. Create a collision-safe .cmbak backup before\n");
    printf("                               rewriting.\n");
    printf("  -h, --help                   Show this help and exit.\n");
    printf("  -v, --version                Show the program version and exit.\n\n");

    printf("Option syntax:\n");
    printf("  Long options taking values accept both --option VALUE and --option=VALUE.\n");
    printf("  Use -- to end option parsing before a positional path beginning with '-'.\n\n");

    printf("Mode details:\n");
    printf("  check accepts one directory, one manifest file, or multiple explicit manifest\n");
    printf("  files. With exactly one selected algorithm, explicit files are parsed as that\n");
    printf("  algorithm regardless of filename extension. With multiple algorithms or all,\n");
    printf("  explicit files require a matching selected-algorithm extension for disambiguation.\n");
    printf("  Directory discovery always remains extension-based. With multiple inputs every\n");
    printf("  input must be a regular file. Recursive discovery applies to a single directory.\n\n");
    printf("  hash writes only hash output. With --digest-only, one selected algorithm writes\n");
    printf("  only the digest; multiple algorithms write [algorithm] + aligned padding + digest.\n");
    printf("  Otherwise one algorithm uses the standard manifest grammar and multiple algorithms\n");
    printf("  prefix each standard record with an aligned [algorithm] tag. Output is file-major\n");
    printf("  and algorithm order follows the selector. In digest-only output, --delimiter and\n");
    printf("  --path-separator have no effect. Without --digest-only, paths are relative to the\n");
    printf("  input root. -o writes the same byte stream to a\n");
    printf("  collision-safe file; a collision-selected pathname is reported on stderr.\n");
    printf("  A regular stdout file inside a scanned directory is excluded from hash inputs.\n");
    printf("  Do not redirect stdout onto the input file itself: the shell truncates it before\n");
    printf("  execution. Early pipe closure is normal termination. No summary is printed.\n");
    printf("  Defaults match generate where the options overlap.\n\n");
    printf("  generate defaults to filter '*', case-sensitive matching, and separate layout.\n");
    printf("  Natural/lexicographic sorting in single layout is per directory during\n");
    printf("  depth-first traversal rather than a final global sort.\n\n");
    printf("  derive never rehashes or rewrites an existing target manifest. Existing\n");
    printf("  targets are checked by path-occurrence coverage; extra target entries are\n");
    printf("  allowed. An existing zero-entry target is compared as empty; a non-empty\n");
    printf("  reference therefore reports MISSING/INCOMPLETE. A missing target is committed\n");
    printf("  only after every valid reference entry can be represented, read, and hashed.\n");
    printf("  --from order determines creation\n");
    printf("  precedence when several references map to the same target.\n\n");
    printf("  format prints a plan and starts rewriting only after case-insensitive y/yes\n");
    printf("  confirmation. Digest values and non-entry lines are preserved; manifests\n");
    printf("  containing NUL and symbolic-link manifest paths are not rewritten.\n\n");
    printf("  remove requires two case-insensitive y/yes confirmations and then exactly\n");
    printf("  lowercase yes with no surrounding whitespace. Discovery/deletion starts only\n");
    printf("  after that final confirmation.\n\n");

    printf("Native hash providers:\n");
    printf("  Build-time dependencies are OpenSSL 1.1.0+ development headers/Crypto library,\n");
    printf("  Libgcrypt development headers/library, and LibRHash development headers/library.\n");
    printf("  Hashing is in-process only; no external checksum executable is launched.\n");
    printf("  Automatic order: OpenSSL -> Libgcrypt -> LibRHash. Actual support is probed\n");
    printf("  at runtime for each required algorithm.\n");
    printf("  hash always hashes selected files.\n");
    printf("  format/join/split/remove do not hash.\n");
    printf("  derive needs a provider only when a target manifest is missing.\n\n");

    printf("Memory safety:\n");
    printf("  Dynamic buffers and vectors use checked size arithmetic before growth and\n");
    printf("  allocation, preventing size_t wraparound in allocation-size calculations.\n\n");

    printf("Built-in algorithms:\n");
    for(i = 0; i < CM_ARRAY_LEN(kAlgorithmInfo); i++)
    {
        if(i == 0 || i == 10 || i == 16)
            printf("  ");
        printf("%s", kAlgorithmInfo[i].name);
        if(i + 1 < CM_ARRAY_LEN(kAlgorithmInfo))
            printf(",");
        if(i == 9 || i == 15 || i + 1 == CM_ARRAY_LEN(kAlgorithmInfo))
            printf("\n");
        else
            printf(" ");
    }

    printf("\n");
    printf("Extensions:\n");
    printf("  crc32               -> .sfv\n");
    printf("  crc32c              -> .crc32c\n");
    printf("  all other built-ins -> .<algorithm>\n");
    printf("  Extension matching is case-insensitive.\n\n");

    printf("Manifest discovery:\n");
    printf("  Hidden files/directories are included. Recursive traversal does not follow\n");
    printf("  directory symlinks encountered below the starting path. Unreadable directory\n");
    printf("  scans are operational errors.\n\n");

    printf("Hash/generate filter grammar:\n");
    printf("  Portable basename matching supports *, ?, bracket expressions/ranges, POSIX\n");
    printf("  bracket classes, and backslash escaping. Extended-glob operators are not\n");
    printf("  supported. Matching is byte-oriented.\n\n");

    printf("Entry grammar:\n");
    printf("  Non-CRC     : HEX followed by two spaces, ' *', TAB+'*', one space, or TAB,\n");
    printf("                then a non-empty filename. Ambiguous delimiters backtrack so\n");
    printf("                the filename remains non-empty.\n");
    printf("  CRC32/CRC32C: FILENAME + whitespace + HEX.\n");
    printf("                Digest length is intentionally not validated. Blank lines and\n");
    printf("                unescaped #/; comment lines are ignored. Escaped records decode\n");
    printf("                \\\\, \\n, and \\r in filenames. check/derive/join/split skip\n");
    printf("                unrecognized and NUL-containing lines; format refuses to rewrite\n");
    printf("                any manifest containing NUL.\n\n");

    printf("Verification labels:\n");
    printf("  VALID    Calculated digest matches.\n");
    printf("  INVALID  Hashing succeeded but the digest does not match.\n");
    printf("  UNREAD   Target is missing, not a regular file, or cannot be read.\n");
    printf("  ERROR    Another verification/provider/hash error occurred.\n\n");

    printf("Derive labels:\n");
    printf("  OUTPUT      A missing target was created.\n");
    printf("  COMPLETE    An existing target covers all reference occurrences.\n");
    printf("  INCOMPLETE  An existing target is missing at least one reference occurrence.\n");
    printf("  MISSING     A reference occurrence is not covered by an existing target.\n\n");

    printf("Output and safety:\n");
    printf("  check -o, hash -o, generate, join, and split preserve existing outputs and choose\n");
    printf("  collision-safe names. derive target paths are semantic and are never replaced\n");
    printf("  by random collision names. split confines output below its safety root and\n");
    printf("  rejects lexical or symlink-parent escapes. POSIX newly created outputs use\n");
    printf("  mode 0644; format preserves existing manifest permission bits.\n\n");

    printf("Newlines:\n");
    printf("  unix/lf        -> LF\n");
    printf("  windows/crlf   -> CRLF\n");
    printf("  classic-mac/cr -> CR\n");
    printf("  system         -> native\n");
    printf("  Input manifests may contain LF, CRLF, or CR.\n\n");

    printf("Signals:\n");
    printf("  SIGINT/SIGTERM request cooperative cancellation. Temporary/reserved outputs\n");
    printf("  are cleaned, normal completion summaries are suppressed, no cancellation or\n");
    printf("  interruption message is printed, and the final status is 128+signal.\n\n");

    printf("Exit status:\n");
    printf("  0           success, including cancellation at a confirmation prompt before changes\n");
    printf("  1           verification/data/processing/operational failure after valid invocation\n");
    printf("  2           command-line, initial path, or output-preflight/configuration error\n");
    printf("  127         no usable native provider for an algorithm that actually requires hashing\n");
    printf("  128+signal  when interrupted by SIGINT/SIGTERM\n\n");

    printf("Examples:\n");
    printf("  %s check sha256 /data/releases/checksums.sha256\n", program);
    printf("  %s check all -r .\n", program);
    printf("  %s check sha256 -r -o /tmp/check-report.txt /data/releases\n", program);
    printf("  %s hash sha256 /data/releases/image.iso\n", program);
    printf("  %s hash md5,sha256 -r -o /tmp/hashes.txt /data/releases\n", program);
    printf("  %s generate md5,sha256 -r /data/releases\n", program);
    printf("  %s generate sha256 -r -l single -N -o /tmp/checksums.sha256 /data/releases\n", program);
    printf("  %s generate sha256 -f '*.iso' -C insensitive /data/releases\n", program);
    printf("  %s generate sha256 -t sha256:openssl /data/releases/image.iso\n", program);
    printf("  %s derive sha256,sha512 -F md5,sha1 -r /data/releases\n", program);
    printf("  %s format sha256 -r -d \" *\" -n windows -s slash -b /data/releases\n", program);
    printf("  %s join sha256 -r -L -o /tmp/joined.sha256 /data/releases\n", program);
    printf("  %s split sha256 -o /tmp/split /tmp/joined.sha256\n", program);
    printf("  %s remove md5,sha256 -r /data/releases\n", program);
    printf("  %s check sha256 -- -checksums.sha256\n", program);
    free(program);
}

static void cm_print_version(const char *argv0)
{
    char *program = cm_program_display_name(argv0);

    printf("%s %s\n", program, CM_VERSION);
    free(program);
}

/* -------------------------- discovery and output -------------------------- */

static int cm_ends_ci(const char *s, const char *suffix)
{
    size_t ns = strlen(s), nx = strlen(suffix), i;

    if(nx > ns)
        return 0;
    for(i = 0; i < nx; i++)
        if(cm_ascii_tolower((unsigned char)s[ns - nx + i]) != cm_ascii_tolower((unsigned char)suffix[i]))
            return 0;
    return 1;
}

static const char *cm_detect_algorithm(const char *path, const CmStrVec *selected)
{
    const char *base = cm_path_basename_ptr(path), *best = NULL;
    size_t bestlen = 0, i;

    for(i = 0; i < selected->n; i++)
    {
        const char *ext = cm_algo_ext(selected->v[i]);
        CmBuf b;
        char *suffix;

        cm_buf_init(&b);
        cm_buf_putc(&b, '.');
        cm_buf_append(&b, ext);
        suffix = cm_buf_take(&b);
        if(cm_ends_ci(base, suffix) && strlen(ext) > bestlen)
        {
            best = selected->v[i];
            bestlen = strlen(ext);
        }
        free(suffix);
    }

    return best;
}

typedef struct
{
    const CmStrVec *selected;
    CmManifestVec *out;
} CmManifestCollectCtx;

static int cm_collect_manifest_cb(const char *path, void *u)
{
    CmManifestCollectCtx *c = (CmManifestCollectCtx *)u;
    const char *a = cm_detect_algorithm(path, c->selected);

    if(a)
        cm_mv_push(c->out, path, a);
    return 0;
}

static int cm_collect_manifests(const char *path, int recursive, const CmStrVec *selected, int natural, CmManifestVec *out)
{
    CmManifestCollectCtx c;

    c.selected = selected;
    c.out = out;
    g_scan_errors = 0;
    return cm_walk(path, recursive, natural, cm_collect_manifest_cb, &c);
}

typedef struct
{
    const char *pattern, *case_mode;
    CmStrVec *out;
} CmFileCollectCtx;

static int cm_collect_file_cb(const char *path, void *u)
{
    CmFileCollectCtx *c = (CmFileCollectCtx *)u;

    if(cm_filter_match(path, c->pattern, c->case_mode))
        cm_sv_push(c->out, path);
    return 0;
}

static int cm_collect_generate_files(const char *path, int recursive, const char *pattern, const char *case_mode, int natural, CmStrVec *out)
{
    CmFileCollectCtx c;

    c.pattern = pattern;
    c.case_mode = case_mode;
    c.out = out;
    g_scan_errors = 0;
    return cm_walk(path, recursive, natural, cm_collect_file_cb, &c);
}

static void cm_random_hex(char out[9])
{
    unsigned char b[4];
    size_t i;
    static const char h[] = "0123456789ABCDEF";

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    if(RAND_bytes(b, 4) != 1)
#endif
    {
        unsigned long x = (unsigned long)time(NULL) ^ (unsigned long)clock();
#ifdef _WIN32
        x ^= (unsigned long)GetCurrentProcessId();
#else
        x ^= (unsigned long)getpid();
#endif
        for(i = 0; i < 4; i++)
        {
            b[i] = (unsigned char)(x & 255);
            x = x * 1103515245UL + 12345UL;
        }
    }

    for(i = 0; i < 4; i++)
    {
        out[i * 2] = h[b[i] >> 4];
        out[i * 2 + 1] = h[b[i] & 15];
    }

    out[8] = 0;
}

/* Reserve output names atomically so collision handling has no check-then-create race window. */
static int cm_reserve_exclusive(const char *path)
{
#ifdef _WIN32
    wchar_t *w = cm_utf8_to_wide(path);
    HANDLE h;
    DWORD error = ERROR_SUCCESS;

    if(!w)
        return 2;
    h = CreateFileW(w, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if(h == INVALID_HANDLE_VALUE)
        error = GetLastError();
    free(w);
    if(h == INVALID_HANDLE_VALUE)
        return error == ERROR_FILE_EXISTS || error == ERROR_ALREADY_EXISTS ? 1 : 2;
    CloseHandle(h);

    return 0;
#else
    int fd = cm_posix_open_path(path, O_WRONLY | O_CREAT | O_EXCL | O_BINARY | O_CLOEXEC, 0600);

    if(fd < 0)
        return errno == EEXIST ? 1 : 2;
    if(close(fd) != 0)
    {
        cm_unlink(path);
        return 2;
    }

    return 0;
#endif
}

static char *cm_reserve_collision(const char *path, const char *algo, int keep_stem, int make_parent, int report_style)
{
    char *abs = cm_path_normalize(path), *dir = cm_path_dirname(abs), *base = cm_path_basename(abs);
    int r;

    if(make_parent && !cm_is_dir(dir) && cm_make_dirs(dir) != 0)
    {
        free(abs);
        free(dir);
        free(base);
        return NULL;
    }

    if(!cm_is_dir(dir))
    {
        free(abs);
        free(dir);
        free(base);
        return NULL;
    }

    r = cm_reserve_exclusive(abs);
    if(r == 0)
    {
        free(dir);
        free(base);
        cm_sv_push(&g_reserved_paths, abs);
        return abs;
    }

    if(r != 1)
    {
        free(abs);
        free(dir);
        free(base);
        return NULL;
    }

    for(;;)
    {
        char hex[9];
        CmBuf b;
        char *cand, *full;

        cm_random_hex(hex);
        cm_buf_init(&b);
        if(report_style)
        {
            char *dot = strrchr(base, '.');

            if(dot && dot != base)
            {
                char saved = *dot;
                *dot = 0;
                cm_buf_append(&b, base);
                *dot = saved;
                cm_buf_putc(&b, '-');
                cm_buf_append(&b, hex);
                cm_buf_append(&b, dot);
            }
            else
            {
                cm_buf_append(&b, base);
                cm_buf_putc(&b, '-');
                cm_buf_append(&b, hex);
            }
        }
        else if(keep_stem)
        {
            const char *ext = cm_algo_ext(algo);
            size_t suffixlen = strlen(ext) + 1;

            if(strlen(base) > suffixlen && base[strlen(base) - suffixlen] == '.' && cm_ends_ci(base, ext))
            {
                cm_buf_append_n(&b, base, strlen(base) - suffixlen);
                cm_buf_putc(&b, '-');
                cm_buf_append(&b, hex);
                cm_buf_putc(&b, '.');
                cm_buf_append(&b, ext);
            }
            else
            {
                cm_buf_append(&b, base);
                cm_buf_putc(&b, '-');
                cm_buf_append(&b, hex);
            }
        }
        else
        {
            cm_buf_append(&b, "checksum-");
            cm_buf_append(&b, hex);
            cm_buf_putc(&b, '.');
            cm_buf_append(&b, cm_algo_ext(algo));
        }
        cand = cm_buf_take(&b);
        full = cm_path_join(dir, cand);
        free(cand);
        r = cm_reserve_exclusive(full);
        if(r == 0)
        {
            cm_sv_push(&g_reserved_paths, full);
            free(abs);
            free(dir);
            free(base);
            return full;
        }
        free(full);
        if(r != 1)
        {
            free(abs);
            free(dir);
            free(base);
            return NULL;
        }
    }
}

static char *cm_temp_in_dir(const char *dir)
{
    int i;

    for(i = 0; i < 100; i++)
    {
        char hex[9];
        CmBuf b;
        char *name, *path;

        cm_random_hex(hex);
        cm_buf_init(&b);
        cm_buf_append(&b, ".checksum-manifest.");
        cm_buf_append(&b, hex);
        cm_buf_append(&b, ".tmp");
        name = cm_buf_take(&b);
        path = cm_path_join(dir, name);
        free(name);
        if(cm_reserve_exclusive(path) == 0)
        {
            cm_sv_push(&g_temp_paths, path);
            return path;
        }
        free(path);
    }

    return NULL;
}

static void cm_registry_remove(CmStrVec *v, const char *path)
{
    size_t i;

    for(i = 0; i < v->n; i++)
        if(strcmp(v->v[i], path) == 0)
        {
            free(v->v[i]);
            memmove(v->v + i, v->v + i + 1, (v->n - i - 1) * sizeof(char *));
            v->n--;
            return;
        }
}

static void cm_cleanup_artifacts()
{
    size_t i;

    for(i = 0; i < g_temp_paths.n; i++)
        cm_unlink(g_temp_paths.v[i]);
    for(i = 0; i < g_reserved_paths.n; i++)
        cm_unlink(g_reserved_paths.v[i]);
    cm_sv_free(&g_temp_paths);
    cm_sv_free(&g_reserved_paths);
}

/* Reject lexical traversal and existing symlink parents before split creates any output directory. */
static int cm_secure_prepare_parent(const char *root, const char *target)
{
    char *r = cm_path_normalize(root), *t = cm_path_normalize(target), *parent = cm_path_dirname(t), *rel, *walk, *p;

    if(!cm_same_path_prefix(r, parent))
    {
        free(r);
        free(t);
        free(parent);
        return 0;
    }

    rel = cm_relative_path(r, parent);
    walk = cm_xstrdup(r);
    p = rel;
    if(strcmp(rel, ".") != 0)
        while(*p)
        {
            char *start = p, *seg, *next;

            while(*p && !cm_is_sep(*p))
                p++;
            seg = cm_xstrndup(start, (size_t)(p - start));
            while(*p && cm_is_sep(*p))
                p++;
            next = cm_path_join(walk, seg);
            free(seg);
            free(walk);
            walk = next;
            if(cm_exists(walk))
            {
                CmFileInfo s;

                if(cm_file_info(walk, 0, &s) != 0 || s.is_symlink || !s.is_dir)
                {
                    free(r);
                    free(t);
                    free(parent);
                    free(rel);
                    free(walk);
                    return 0;
                }
            }
            else if(cm_mkdir_one(walk) != 0)
            {
                free(r);
                free(t);
                free(parent);
                free(rel);
                free(walk);
                return 0;
            }
        }
    free(r);
    free(t);
    free(parent);
    free(rel);
    free(walk);

    return 1;
}

static int cm_write_records(const char *path, const char *algo, const CmRecordVec *records, const CmOptions *o)
{
    char *dir = cm_path_dirname(path), *tmp;
    FILE *f;
    size_t i;
    const char *nl = cm_newline_bytes(o->newline_mode);

    if(!cm_is_dir(dir) && cm_make_dirs(dir) != 0)
    {
        fprintf(stderr, "Error: %s: failed to create output directory.\n", cm_terminal_path_view(dir));
        free(dir);
        return 0;
    }

    tmp = cm_temp_in_dir(dir);
    free(dir);
    if(!tmp)
    {
        fprintf(stderr, "Error: %s: failed to create temporary output.\n", cm_terminal_path_view(path));
        return 0;
    }

    f = cm_fopen(tmp, "wb");
    if(!f)
    {
        cm_unlink(tmp);
        cm_registry_remove(&g_temp_paths, tmp);
        free(tmp);
        return 0;
    }

    for(i = 0; i < records->n; i++)
    {
        char *line;

        if(g_interrupted)
        {
            fclose(f);
            cm_unlink(tmp);
            cm_registry_remove(&g_temp_paths, tmp);
            free(tmp);
            return 0;
        }
        line = cm_format_record(algo, records->v[i].digest, records->v[i].name, o->delimiter);
        if(fwrite(line, 1, strlen(line), f) != strlen(line) || fwrite(nl, 1, strlen(nl), f) != strlen(nl))
        {
            free(line);
            fclose(f);
            cm_unlink(tmp);
            cm_registry_remove(&g_temp_paths, tmp);
            free(tmp);
            return 0;
        }
        free(line);
    }

    if(fflush(f) != 0 || g_interrupted)
    {
        fclose(f);
        cm_unlink(tmp);
        cm_registry_remove(&g_temp_paths, tmp);
        free(tmp);
        return 0;
    }
#ifndef _WIN32
    if(fsync(fileno(f)) != 0)
    {
        fclose(f);
        cm_unlink(tmp);
        cm_registry_remove(&g_temp_paths, tmp);
        free(tmp);
        return 0;
    }
#endif
    fclose(f);
    if(cm_chmod_0644(tmp) != 0)
    {
        fprintf(stderr, "Error: %s: failed to set output permissions: %s\n", cm_terminal_path_view(path), strerror(errno));
        cm_unlink(tmp);
        cm_registry_remove(&g_temp_paths, tmp);
        free(tmp);
        return 0;
    }

    if(cm_rename(tmp, path) != 0)
    {
        fprintf(stderr, "Error: %s: failed to replace output: %s\n", cm_terminal_path_view(path), strerror(errno));
        cm_unlink(tmp);
        cm_registry_remove(&g_temp_paths, tmp);
        free(tmp);
        return 0;
    }

    cm_registry_remove(&g_temp_paths, tmp);
    cm_registry_remove(&g_reserved_paths, path);
    free(tmp);

    return 1;
}

static int cm_read_records(const char *manifest, const char *algo, CmRecordVec *out, int *valid_count, int *has_nul)
{
    CmStrVec lines = {0};
    size_t i;
    int count = 0;

    if(cm_read_lines(manifest, &lines, has_nul) != 0)
    {
        cm_sv_free(&lines);
        return 0;
    }

    for(i = 0; i < lines.n; i++)
    {
        CmRecord r;

        if(cm_parse_manifest_line(algo, lines.v[i], &r))
        {
            r.line_no = i + 1;
            cm_rv_push(out, &r);
            cm_record_free(&r);
            count++;
        }
    }

    cm_sv_free(&lines);
    if(valid_count)
        *valid_count = count;

    return 1;
}

static char *cm_default_output_name(const char *algo)
{
    CmBuf b;

    cm_buf_init(&b);
    cm_buf_append(&b, "checksums.");
    cm_buf_append(&b, cm_algo_ext(algo));
    return cm_buf_take(&b);
}

static int cm_output_has_extension(const char *path, const char *algo)
{
    CmStrVec s = {0};
    const char *a;

    cm_sv_push(&s, algo);
    a = cm_detect_algorithm(path, &s);
    cm_sv_free(&s);

    return a != NULL;
}

static char *cm_report_base(const char *path)
{
    char *a = cm_path_normalize(path);

    if(cm_is_file(a))
    {
        char *d = cm_path_dirname(a);

        free(a);
        return d;
    }

    return a;
}

static char *cm_report_path(const char *target, const char *base, const char *mode, const char *source)
{
    char *rel = cm_relative_path(base, target), *out = cm_render_native_path(rel, mode, source), *result;

    free(rel);
    if(strcmp(out, ".") == 0 || strcmp(out, "..") == 0 || strncmp(out, "../", 3) == 0 || strncmp(out, "..\\", 3) == 0)
        return out;
    {
        CmBuf b;
        const char *prefix = cm_output_sep(mode, source) == '\\' ? ".\\" : "./";

        cm_buf_init(&b);
        cm_buf_append(&b, prefix);
        cm_buf_append(&b, out);
        result = cm_buf_take(&b);
        free(out);
        return result;
    }
}

static char *cm_sanitize_report_text(const char *text)
{
    const unsigned char *p = (const unsigned char *)text;
    CmBuf b;

    cm_buf_init(&b);
    for(; *p; p++)
        if(*p == '\n')
        {
            cm_buf_append(&b, "\\n");
        }
        else if(*p == '\r')
        {
            cm_buf_append(&b, "\\r");
        }
        else if(*p < 32 || *p == 127)
        {
            char x[5];

            snprintf(x, sizeof(x), "\\x%02X", (unsigned)*p);
            cm_buf_append(&b, x);
        }
        else
        {
            cm_buf_putc(&b, (char)*p);
        }

    return cm_buf_take(&b);
}

static void cm_derive_status(const char *label, const char *path)
{
    int spaces = 11 - (int)strlen(label);
    char *safe = cm_sanitize_report_text(cm_terminal_path_view(path));

    if(spaces < 1)
        spaces = 1;
    printf("[%s]:%*s%s\n", label, spaces, "", safe);
    free(safe);
}

static void cm_format_status(const char *label, const char *path)
{
    int spaces = 10 - (int)strlen(label);
    char *safe = cm_sanitize_report_text(cm_terminal_path_view(path));

    if(spaces < 1)
        spaces = 1;
    printf("[%s]:%*s%s\n", label, spaces, "", safe);
    free(safe);
}

static void cm_print_output_path(const char *path, const char *suffix)
{
    char *safe = cm_sanitize_report_text(cm_terminal_path_view(path));

    printf("[OUTPUT]: %s%s\n", safe, suffix ? suffix : "");
    free(safe);
}

static void cm_add_record(CmRecordVec *v, const char *digest, const char *name)
{
    CmRecord r;

    r.digest = (char *)digest;
    r.name = (char *)name;
    r.raw_name = (char *)name;
    r.escaped = 0;
    r.line_no = 0;
    cm_rv_push(v, &r);
}

static char *cm_generate_source_base(const char *path)
{
    char *a = cm_path_normalize(path);

    if(cm_is_file(a))
    {
        char *d = cm_path_dirname(a);

        free(a);
        return d;
    }

    return a;
}

static char *cm_generated_entry_name(const char *filename, const char *manifest, const char *mode)
{
    char *dir = cm_path_dirname(manifest), *rel = cm_relative_path(dir, filename), *out = cm_path_for_manifest_output(rel, mode, rel);

    free(dir);
    free(rel);

    return out;
}

static char *cm_generate_separate_path(const char *filename, const char *algo, const CmOptions *o)
{
    char *abs = cm_path_normalize(filename), *res;

    if(!o->output)
    {
        CmBuf b;

        cm_buf_init(&b);
        cm_buf_append(&b, abs);
        cm_buf_putc(&b, '.');
        cm_buf_append(&b, cm_algo_ext(algo));
        res = cm_buf_take(&b);
    }
    else
    {
        char *root = cm_path_normalize(o->output), *base = cm_generate_source_base(o->path), *rel;

        if(cm_is_file(o->path))
            rel = cm_path_basename(abs);
        else
            rel = cm_relative_path(base, abs);
        {
            char *tmp = cm_path_join(root, rel);
            CmBuf b;

            cm_buf_init(&b);
            cm_buf_append(&b, tmp);
            cm_buf_putc(&b, '.');
            cm_buf_append(&b, cm_algo_ext(algo));
            res = cm_buf_take(&b);
            free(tmp);
        }
        free(root);
        free(base);
        free(rel);
    }

    free(abs);

    return res;
}

static char *cm_hash_entry_name(const char *filename, const char *source, const char *mode)
{
    char *absolute = cm_path_normalize(filename);
    char *base = cm_generate_source_base(source);
    char *relative;
    char *out;

    if(cm_is_file(source))
        relative = cm_path_basename(absolute);
    else
        relative = cm_relative_path(base, absolute);
    out = cm_path_for_manifest_output(relative, mode, relative);
    free(absolute);
    free(base);
    free(relative);

    return out;
}

static int cm_hash_stdout_mode_0644()
{
#ifndef _WIN32
    struct stat st;
    int fd = fileno(stdout);

    if(fd >= 0 && fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && fchmod(fd, 0644) != 0)
        return 0;
#endif
    return 1;
}

static int cm_hash_path_is_stdout_file(const char *path)
{
#ifdef _WIN32
    intptr_t raw_handle = _get_osfhandle(_fileno(stdout));
    HANDLE stdout_handle = raw_handle == -1 ? INVALID_HANDLE_VALUE : (HANDLE)raw_handle;
    BY_HANDLE_FILE_INFORMATION stdout_info, path_info;
    wchar_t *wide_path;
    HANDLE path_handle;
    int same = 0;

    if(stdout_handle == INVALID_HANDLE_VALUE || GetFileType(stdout_handle) != FILE_TYPE_DISK || !GetFileInformationByHandle(stdout_handle, &stdout_info))
        return 0;
    wide_path = cm_utf8_to_wide(path);
    if(!wide_path)
        return 0;
    path_handle = CreateFileW(wide_path, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    free(wide_path);
    if(path_handle == INVALID_HANDLE_VALUE)
        return 0;
    if(GetFileInformationByHandle(path_handle, &path_info))
    {
        same = stdout_info.dwVolumeSerialNumber == path_info.dwVolumeSerialNumber &&
            stdout_info.nFileIndexHigh == path_info.nFileIndexHigh && stdout_info.nFileIndexLow == path_info.nFileIndexLow;
    }
    CloseHandle(path_handle);

    return same;
#else
    struct stat stdout_stat, path_stat;
    int stdout_fd = fileno(stdout), path_fd;
    int same = 0;

    if(stdout_fd < 0 || fstat(stdout_fd, &stdout_stat) != 0 || !S_ISREG(stdout_stat.st_mode))
        return 0;
    path_fd = cm_posix_open_path(path, O_RDONLY | O_CLOEXEC, 0);
    if(path_fd < 0)
        return 0;
    if(fstat(path_fd, &path_stat) == 0)
        same = stdout_stat.st_dev == path_stat.st_dev && stdout_stat.st_ino == path_stat.st_ino;
    close(path_fd);

    return same;
#endif
}

static int cm_hash_exclude_stdout_file(CmStrVec *files, const char *source)
{
    size_t read_index, write_index = 0;
    int source_is_file = cm_is_file(source);

    for(read_index = 0; read_index < files->n; read_index++)
    {
        if(cm_hash_path_is_stdout_file(files->v[read_index]))
        {
            if(source_is_file)
            {
                fprintf(stderr, "Error: standard output overlaps the input file; shell redirection has already truncated it\n");
                return 0;
            }
            free(files->v[read_index]);
            continue;
        }
        files->v[write_index++] = files->v[read_index];
    }
    files->n = write_index;

    return 1;
}

static int cm_hash_output_open(const CmOptions *o, CmHashOutput *output)
{
    memset(output, 0, sizeof(*output));
    if(!o->output)
    {
        if(!cm_hash_stdout_mode_0644())
        {
            fprintf(stderr, "Error: standard output: cannot set mode 0644: %s\n", strerror(errno));
            return 0;
        }
        output->file = stdout;
        return 1;
    }

    if(cm_is_dir(o->output))
    {
        fprintf(stderr, "Error: hash --output must name a file, not a directory\n");
        return 0;
    }
    output->path = cm_reserve_collision(o->output, "", 0, 1, 1);
    if(!output->path)
    {
        fprintf(stderr, "Error: cannot reserve hash output: %s\n", cm_terminal_path_view(o->output));
        return 0;
    }
    output->file = cm_fopen(output->path, "wb");
    if(!output->file)
    {
        fprintf(stderr, "Error: %s: cannot open hash output: %s\n", cm_terminal_path_view(output->path), strerror(errno));
        cm_unlink(output->path);
        cm_registry_remove(&g_reserved_paths, output->path);
        free(output->path);
        output->path = NULL;
        return 0;
    }
    output->owns_file = 1;
    if(cm_chmod_0644(output->path) != 0)
    {
        fprintf(stderr, "Error: %s: cannot set output permissions: %s\n", cm_terminal_path_view(output->path), strerror(errno));
        fclose(output->file);
        output->file = NULL;
        cm_unlink(output->path);
        cm_registry_remove(&g_reserved_paths, output->path);
        free(output->path);
        output->path = NULL;
        return 0;
    }
    {
        char *requested = cm_path_normalize(o->output);

        if(strcmp(requested, output->path) != 0)
            fprintf(stderr, "[OUTPUT]: %s\n", cm_terminal_path_view(output->path));
        free(requested);
    }

    return 1;
}

static int cm_hash_output_write(CmHashOutput *output, const char *line, const char *newline)
{
    size_t line_length = strlen(line);
    size_t newline_length = strlen(newline);

    errno = 0;
    if(fwrite(line, 1, line_length, output->file) != line_length || fwrite(newline, 1, newline_length, output->file) != newline_length || fflush(output->file) != 0)
    {
        int broken_pipe = 0;

#ifdef _WIN32
        unsigned long dos_error = 0;

        _get_doserrno(&dos_error);
        broken_pipe = errno == EPIPE || dos_error == ERROR_BROKEN_PIPE || dos_error == ERROR_NO_DATA;
#else
        broken_pipe = errno == EPIPE;
#endif
        if(!output->owns_file && broken_pipe)
        {
            output->broken_pipe = 1;
            clearerr(output->file);
            return 0;
        }
        output->failed = 1;
        return 0;
    }

    return 1;
}

static int cm_hash_output_close(CmHashOutput *output, int keep)
{
    int ok = !output->failed;

    if(output->owns_file)
    {
        if(output->file)
        {
            if(fflush(output->file) != 0)
                ok = 0;
#ifndef _WIN32
            if(ok && fsync(fileno(output->file)) != 0)
                ok = 0;
#endif
            if(fclose(output->file) != 0)
                ok = 0;
            output->file = NULL;
        }
        if(ok && keep && cm_chmod_0644(output->path) != 0)
            ok = 0;
        if(ok && keep)
        {
            cm_registry_remove(&g_reserved_paths, output->path);
        }
        else
        {
            cm_unlink(output->path);
            cm_registry_remove(&g_reserved_paths, output->path);
        }
        free(output->path);
        output->path = NULL;
    }
    else if(output->broken_pipe)
    {
        clearerr(output->file);
    }
    else if(output->file && fflush(output->file) != 0)
    {
        ok = 0;
    }

    return ok;
}

static int cm_mode_hash(const CmOptions *o)
{
    CmStrVec files = {0};
    CmProviderChoiceVec providers = {0};
    CmHashOutput output;
    const char *newline = cm_newline_bytes(o->newline_mode);
    size_t i, j, algorithm_width = 0;
    int errors = 0, output_ok = 1;
#ifndef _WIN32
    struct sigaction previous_pipe_action, ignored_pipe_action;
    int pipe_action_saved = 0;
#endif

    cm_collect_generate_files(o->path, o->recursive, o->filter_pattern, o->filter_case, o->natural_sort, &files);
    errors += g_scan_errors;
    for(i = 0; i < files.n; i++)
    {
        char *absolute = cm_path_normalize(files.v[i]);

        free(files.v[i]);
        files.v[i] = absolute;
    }

    if(g_interrupted)
    {
        cm_sv_free(&files);
        return 1;
    }
    if(!o->output && !cm_hash_exclude_stdout_file(&files, o->path))
    {
        cm_sv_free(&files);
        return 2;
    }
    if(files.n && !cm_prepare_providers(&o->algorithms, &o->tools, &providers))
    {
        cm_pcv_free(&providers);
        cm_sv_free(&files);
        return 127;
    }
    if(!cm_hash_output_open(o, &output))
    {
        cm_pcv_free(&providers);
        cm_sv_free(&files);
        return 2;
    }
#ifndef _WIN32
    memset(&ignored_pipe_action, 0, sizeof(ignored_pipe_action));
    ignored_pipe_action.sa_handler = SIG_IGN;
    sigemptyset(&ignored_pipe_action.sa_mask);
    if(sigaction(SIGPIPE, &ignored_pipe_action, &previous_pipe_action) == 0)
        pipe_action_saved = 1;
#endif

    if(o->algorithms.n > 1)
        for(i = 0; i < o->algorithms.n; i++)
            if(strlen(o->algorithms.v[i]) > algorithm_width)
                algorithm_width = strlen(o->algorithms.v[i]);

    for(i = 0; i < files.n && output_ok && !g_interrupted; i++)
    {
        char *entry = NULL;

        if(!o->digest_only)
        {
            entry = cm_hash_entry_name(files.v[i], o->path, o->path_separator);
            if(!entry)
            {
                fprintf(stderr, "Error: %s: cannot represent path with selected path separator\n", cm_terminal_path_view(files.v[i]));
                errors++;
                continue;
            }
        }
        for(j = 0; j < o->algorithms.n; j++)
        {
            const char *algo = o->algorithms.v[j];
            const CmAlgorithmInfo *ai = cm_find_algo(algo);
            CmProvider provider = cm_choice_for(&providers, algo);
            char *digest = NULL;
            char *record;
            char *line;
            int rc = cm_hash_with_provider(files.v[i], ai, provider, &digest, 1);

            if(rc != 1)
            {
                if(!g_interrupted)
                {
                    fprintf(stderr, "Error: %s: failed to calculate %s checksum\n", cm_terminal_path_view(files.v[i]), algo);
                    errors++;
                }
                free(digest);
                if(g_interrupted)
                    break;
                continue;
            }
            if(o->digest_only)
                record = cm_xstrdup(digest);
            else
                record = cm_format_record(algo, digest, entry, o->delimiter);
            free(digest);
            if(algorithm_width)
            {
                CmBuf b;
                size_t spaces = algorithm_width - strlen(algo) + 2;

                cm_buf_init(&b);
                cm_buf_putc(&b, '[');
                cm_buf_append(&b, algo);
                cm_buf_putc(&b, ']');
                while(spaces--)
                    cm_buf_putc(&b, ' ');
                cm_buf_append(&b, record);
                line = cm_buf_take(&b);
            }
            else
            {
                line = cm_xstrdup(record);
            }
            free(record);
            if(!cm_hash_output_write(&output, line, newline))
            {
                if(!output.broken_pipe)
                    fprintf(stderr, "Error: %s: failed to write hash output\n", output.path ? cm_terminal_path_view(output.path) : "standard output");
                output_ok = 0;
            }
            free(line);
            if(!output_ok)
                break;
        }
        free(entry);
    }

    if(!cm_hash_output_close(&output, output_ok && !g_interrupted))
    {
        if(output_ok && !g_interrupted)
            fprintf(stderr, "Error: failed to finalize hash output\n");
        output_ok = 0;
    }
#ifndef _WIN32
    if(pipe_action_saved)
        sigaction(SIGPIPE, &previous_pipe_action, NULL);
#endif
    if(output.broken_pipe)
    {
        cm_pcv_free(&providers);
        cm_sv_free(&files);
        return 0;
    }
    if(!output_ok)
        errors++;
    cm_pcv_free(&providers);
    cm_sv_free(&files);

    return errors ? 1 : 0;
}

static int cm_mode_generate(const CmOptions *o)
{
    CmStrVec files = {0};
    CmProviderChoiceVec providers = {0};
    CmCountMap entry_counts = {0};
    size_t i, j;
    int errors = 0, entries = 0, outputs = 0;
    int natural = o->natural_sort;
    char *source_base = cm_generate_source_base(o->path);
    CmStrVec single_paths = {0};

    cm_collect_generate_files(o->path, o->recursive, o->filter_pattern, o->filter_case, natural, &files);
    errors += g_scan_errors;
    if(strcmp(o->layout, "single") == 0)
    {
        int multiple = o->algorithms.n > 1;

        for(i = 0; i < o->algorithms.n; i++)
        {
            char *name = cm_default_output_name(o->algorithms.v[i]), *p;

            if(o->output && multiple)
            {
                if(!cm_is_dir(o->output))
                {
                    fprintf(stderr, "Error: --output must name an existing directory when single layout uses multiple algorithms/all\n");
                    free(name);
                    cm_sv_free(&single_paths);
                    cm_sv_free(&files);
                    free(source_base);
                    return 2;
                }
                p = cm_path_join(o->output, name);
            }
            else if(o->output && cm_is_dir(o->output))
            {
                p = cm_path_join(o->output, name);
            }
            else if(o->output)
            {
                char *parent;

                if(!cm_output_has_extension(o->output, o->algorithms.v[i]))
                {
                    fprintf(stderr, "Error: output file for %s must use a recognized manifest extension.\n", o->algorithms.v[i]);
                    free(name);
                    cm_sv_free(&files);
                    free(source_base);
                    return 2;
                }
                parent = cm_path_dirname(o->output);
                if(!cm_is_dir(parent))
                {
                    fprintf(stderr, "Error: output parent directory does not exist: %s\n", cm_terminal_path_view(parent));
                    free(parent);
                    free(name);
                    cm_sv_free(&files);
                    free(source_base);
                    return 2;
                }
                free(parent);
                p = cm_path_normalize(o->output);
            }
            else
            {
                p = cm_path_join(source_base, name);
            }
            {
                char *n = cm_path_normalize(p);

                cm_sv_push(&single_paths, n);
                free(n);
            }
            free(p);
            free(name);
        }
    }
    else if(o->output)
    {
        if(cm_exists(o->output) && !cm_is_dir(o->output))
        {
            fprintf(stderr, "Error: generate --output must name a directory in separate layout\n");
            cm_sv_free(&files);
            free(source_base);
            return 2;
        }
        if(!cm_is_dir(o->output) && cm_make_dirs(o->output) != 0)
        {
            fprintf(stderr, "Error: cannot create generate output directory: %s\n", cm_terminal_path_view(o->output));
            cm_sv_free(&files);
            free(source_base);
            return 2;
        }
    }

    for(i = 0; i < files.n; i++)
    {
        char *absolute = cm_path_normalize(files.v[i]);

        free(files.v[i]);
        files.v[i] = absolute;
    }

    if(g_interrupted)
    {
        cm_count_free(&entry_counts);
        cm_sv_free(&single_paths);
        cm_sv_free(&files);
        free(source_base);
        return 1;
    }

    if(files.n == 0)
    {
        printf("\n");
        cm_print_mode_entries(&(CmStrVec){0}, &entry_counts, 0);
        printf("Summary:\n  Files  : 0\n  Entries: 0\n  Outputs: 0\n  Errors : %d\n\nOperation complete.\n", errors);
        cm_count_free(&entry_counts);
        cm_sv_free(&single_paths);
        cm_sv_free(&files);
        free(source_base);
        return errors ? 1 : 0;
    }

    if(!cm_prepare_providers(&o->algorithms, &o->tools, &providers))
    {
        cm_pcv_free(&providers);
        cm_count_free(&entry_counts);
        cm_sv_free(&single_paths);
        cm_sv_free(&files);
        free(source_base);
        return 127;
    }

    if(strcmp(o->layout, "single") == 0)
    {
        for(i = 0; i < o->algorithms.n; i++)
        {
            CmRecordVec rec = {0};
            const char *algo = o->algorithms.v[i];
            const char *single_path = i < single_paths.n ? single_paths.v[i] : NULL;
            CmProvider p = cm_choice_for(&providers, algo);

            if(!single_path)
            {
                fprintf(stderr, "Error: internal output planning state is incomplete for %s.\n", algo);
                errors++;
                continue;
            }
            for(j = 0; j < files.n; j++)
            {
                const CmAlgorithmInfo *ai = cm_find_algo(algo);
                char *digest = NULL, *entry;
                int rc = cm_hash_with_provider(files.v[j], ai, p, &digest, 1);

                if(rc != 1)
                {
                    if(!g_interrupted)
                    {
                        fprintf(stderr, "Error: %s: failed to calculate %s checksum\n", cm_terminal_path_view(files.v[j]), algo);
                        errors++;
                    }
                    free(digest);
                    if(g_interrupted)
                        break;
                    continue;
                }
                entry = cm_generated_entry_name(files.v[j], single_path, o->path_separator);
                if(!entry)
                {
                    fprintf(stderr, "Error: %s: cannot represent path with selected path separator\n", cm_terminal_path_view(files.v[j]));
                    errors++;
                    free(digest);
                    continue;
                }
                cm_add_record(&rec, digest, entry);
                entries++;
                cm_count_inc(&entry_counts, algo);
                free(digest);
                free(entry);
            }
            if(rec.n)
            {
                char *reserved = cm_reserve_collision(single_path, algo, 1, 0, 0);

                if(!reserved)
                {
                    fprintf(stderr, "Error: %s: failed to reserve output\n", cm_terminal_path_view(single_path));
                    errors++;
                }
                else if(cm_write_records(reserved, algo, &rec, o))
                {
                    char suffix[128];

                    snprintf(suffix, sizeof(suffix), " (%s: %lu entries)", algo, (unsigned long)rec.n);
                    cm_print_output_path(reserved, suffix);
                    outputs++;
                }
                else
                {
                    cm_unlink(reserved);
                    cm_registry_remove(&g_reserved_paths, reserved);
                    errors++;
                }
                free(reserved);
            }
            cm_rv_free(&rec);
        }
    }
    else
    {
        char *output_root = o->output ? cm_path_normalize(o->output) : NULL;

        for(i = 0; i < files.n; i++)
            for(j = 0; j < o->algorithms.n; j++)
            {
                const char *algo = o->algorithms.v[j];
                const CmAlgorithmInfo *ai = cm_find_algo(algo);
                CmProvider p = cm_choice_for(&providers, algo);
                char *digest = NULL, *intended, *reserved, *entry;
                CmRecordVec rec = {0};

                if(cm_hash_with_provider(files.v[i], ai, p, &digest, 1) != 1)
                {
                    if(!g_interrupted)
                    {
                        fprintf(stderr, "Error: %s: failed to calculate %s checksum\n", cm_terminal_path_view(files.v[i]), algo);
                        errors++;
                    }
                    free(digest);
                    if(g_interrupted)
                        break;
                    continue;
                }
                intended = cm_generate_separate_path(files.v[i], algo, o);
                if(output_root && !cm_secure_prepare_parent(output_root, intended))
                {
                    fprintf(stderr, "Error: %s: output path escapes through a symlink or invalid parent\n", cm_terminal_path_view(intended));
                    errors++;
                    free(digest);
                    free(intended);
                    continue;
                }
                else if(!output_root)
                {
                    char *d = cm_path_dirname(intended);

                    if(!cm_is_dir(d) && cm_make_dirs(d) != 0)
                    {
                        free(d);
                        free(digest);
                        free(intended);
                        errors++;
                        continue;
                    }
                    free(d);
                }
                reserved = cm_reserve_collision(intended, algo, 1, 0, 0);
                if(!reserved)
                {
                    fprintf(stderr, "Error: %s: failed to reserve output\n", cm_terminal_path_view(intended));
                    errors++;
                    free(digest);
                    free(intended);
                    continue;
                }
                entry = cm_generated_entry_name(files.v[i], reserved, o->path_separator);
                if(!entry)
                {
                    fprintf(stderr, "Error: %s: cannot represent path with selected path separator\n", cm_terminal_path_view(files.v[i]));
                    cm_unlink(reserved);
                    cm_registry_remove(&g_reserved_paths, reserved);
                    errors++;
                    free(reserved);
                    free(digest);
                    free(intended);
                    continue;
                }
                cm_add_record(&rec, digest, entry);
                if(cm_write_records(reserved, algo, &rec, o))
                {
                    cm_print_output_path(reserved, NULL);
                    outputs++;
                    entries++;
                    cm_count_inc(&entry_counts, algo);
                }
                else
                {
                    cm_unlink(reserved);
                    cm_registry_remove(&g_reserved_paths, reserved);
                    errors++;
                }
                cm_rv_free(&rec);
                free(entry);
                free(reserved);
                free(digest);
                free(intended);
            }
        free(output_root);
    }

    if(g_interrupted)
    {
        cm_count_free(&entry_counts);
        cm_pcv_free(&providers);
        cm_sv_free(&single_paths);
        cm_sv_free(&files);
        free(source_base);
        return 1;
    }

    printf("\nTools:\n");
    for(i = 0; i < providers.n; i++)
        printf("  %s: %s\n", providers.v[i].algo->name, cm_provider_name(providers.v[i].provider));
    printf("\n");
    cm_print_mode_entries(&o->algorithms, &entry_counts, entries);
    printf("Summary:\n  Files  : %lu\n  Entries: %d\n  Outputs: %d\n  Errors : %d\n\nOperation complete.\n", (unsigned long)files.n, entries, outputs, errors);
    cm_count_free(&entry_counts);
    cm_pcv_free(&providers);
    cm_sv_free(&single_paths);
    cm_sv_free(&files);
    free(source_base);

    return errors ? 1 : 0;
}

/* --------------------------------- check ---------------------------------- */

typedef struct
{
    FILE *f;
    const char *nl;
    int owns;
    int error;
} CmReporter;

static int cm_reporter_open(CmReporter *r, const char *path, const char *newline)
{
    memset(r, 0, sizeof(*r));
    r->nl = path ? cm_newline_bytes(newline) : "\n";
    if(path)
    {
        r->f = cm_fopen(path, "wb");
        r->owns = 1;
        if(r->f && cm_chmod_0644(path) != 0)
        {
            fclose(r->f);
            r->f = NULL;
        }
    }
    else
    {
        r->f = stdout;
    }

    return r->f != NULL;
}

static void cm_reporter_line(CmReporter *r, const char *s)
{
    if(r->error || !r->f)
        return;
    if(s && fwrite(s, 1, strlen(s), r->f) != strlen(s))
    {
        r->error = 1;
        return;
    }
    if(fwrite(r->nl, 1, strlen(r->nl), r->f) != strlen(r->nl))
        r->error = 1;
}

static int cm_reporter_close(CmReporter *r)
{
    int ok = !r->error;

    if(r->f)
    {
        if(fflush(r->f) != 0)
            ok = 0;
#ifndef _WIN32
        if(r->owns && fsync(fileno(r->f)) != 0)
            ok = 0;
#endif
        if(r->owns && fclose(r->f) != 0)
            ok = 0;
    }

    r->f = NULL;
    r->error = !ok;

    return ok;
}

static void cm_reporter_status(CmReporter *r, const char *label, const char *path)
{
    CmBuf b;
    int spaces = 8 - (int)strlen(label);
    char *safe = cm_sanitize_report_text(cm_terminal_path_view(path));

    if(spaces < 1)
        spaces = 1;
    cm_buf_init(&b);
    cm_buf_putc(&b, '[');
    cm_buf_append(&b, label);
    cm_buf_append(&b, "]:");
    while(spaces-- > 0)
        cm_buf_putc(&b, ' ');
    cm_buf_append(&b, safe);
    free(safe);
    {
        char *s = cm_buf_take(&b);

        cm_reporter_line(r, s);
        free(s);
    }
}

static int cm_mode_check(const CmOptions *o)
{
    CmManifestVec manifests = {0};
    CmStrVec present = {0};
    CmProviderChoiceVec providers = {0};
    CmCountMap entry_counts = {0};
    size_t i, j;
    int errors = 0, manicount = 0, entries = 0, valid = 0, invalid = 0, unread = 0;
    char *base;
    CmReporter rep;
    char *report_path = NULL;

    if(o->check_paths.n > 1)
    {
        CmStrVec seen = {0};

        g_scan_errors = 0;
        for(i = 0; i < o->check_paths.n; i++)
        {
            char *a = cm_path_normalize(o->check_paths.v[i]);
            const char *alg;

            if(cm_sv_contains(&seen, a))
            {
                free(a);
                continue;
            }
            cm_sv_push(&seen, a);
            alg = o->algorithms.n == 1 ? o->algorithms.v[0] : cm_detect_algorithm(a, &o->algorithms);
            if(alg)
                cm_mv_push(&manifests, a, alg);
            free(a);
        }
        cm_sv_free(&seen);
    }
    else
    {
        if(o->algorithms.n == 1 && cm_is_file(o->check_paths.v[0]))
            cm_mv_push(&manifests, o->check_paths.v[0], o->algorithms.v[0]);
        else
            cm_collect_manifests(o->check_paths.v[0], o->recursive, &o->algorithms, 0, &manifests);
    }
    errors += g_scan_errors;
    if(!manifests.n)
    {
        fprintf(stderr, "Error: no selected checksum manifest files found in: %s\n", cm_terminal_path_view(o->path));
        cm_mv_free(&manifests);
        return 1;
    }

    for(i = 0; i < o->algorithms.n; i++)
        for(j = 0; j < manifests.n; j++)
            if(strcmp(o->algorithms.v[i], manifests.v[j].algo) == 0)
            {
                cm_sv_push(&present, o->algorithms.v[i]);
                break;
            }
    if(!cm_prepare_providers(&present, &o->tools, &providers))
    {
        cm_pcv_free(&providers);
        cm_mv_free(&manifests);
        cm_sv_free(&present);
        return 127;
    }

    if(o->output)
    {
        if(cm_is_dir(o->output))
        {
            fprintf(stderr, "Error: check --output must name a file, not a directory.\n");
            cm_mv_free(&manifests);
            cm_sv_free(&present);
            cm_pcv_free(&providers);
            return 2;
        }
        report_path = cm_reserve_collision(o->output, "", 0, 1, 1);
        if(!report_path)
        {
            fprintf(stderr, "Error: cannot reserve report output: %s\n", cm_terminal_path_view(o->output));
            cm_mv_free(&manifests);
            cm_sv_free(&present);
            cm_pcv_free(&providers);
            return 2;
        }
    }

    if(!cm_reporter_open(&rep, report_path, o->newline_mode))
    {
        fprintf(stderr, "Error: cannot open report output.\n");
        if(report_path)
        {
            cm_unlink(report_path);
            cm_registry_remove(&g_reserved_paths, report_path);
        }
        free(report_path);
        cm_mv_free(&manifests);
        cm_sv_free(&present);
        cm_pcv_free(&providers);
        return 2;
    }

    if(o->check_paths.n > 1)
        base = cm_getcwd_utf8();
    else
        base = cm_report_base(o->path);
    for(i = 0; i < manifests.n; i++)
    {
        CmRecordVec rec = {0};

        if(g_interrupted)
            break;

        int count = 0, hn = 0;
        CmProvider p = cm_choice_for(&providers, manifests.v[i].algo);
        const CmAlgorithmInfo *ai = cm_find_algo(manifests.v[i].algo);

        manicount++;
        if(!cm_read_records(manifests.v[i].path, manifests.v[i].algo, &rec, &count, &hn))
        {
            char *rp = cm_report_path(manifests.v[i].path, base, "slash", manifests.v[i].path);

            cm_reporter_status(&rep, "UNREAD", rp);
            free(rp);
            unread++;
            cm_rv_free(&rec);
            continue;
        }
        if(!count)
        {
            char *rp = cm_report_path(manifests.v[i].path, base, "slash", manifests.v[i].path);

            cm_reporter_status(&rep, "ERROR", rp);
            free(rp);
            errors++;
            cm_rv_free(&rec);
            continue;
        }
        for(j = 0; j < rec.n; j++)
        {
            char *target = cm_entry_target(manifests.v[i].path, rec.v[j].name, o->path_separator, 0, 0), *rp = cm_report_path(target, base, "slash", rec.v[j].name), *digest = NULL;
            CmBuf disp;
            int rc;

            cm_buf_init(&disp);
            cm_buf_append(&disp, rp);
            cm_buf_append(&disp, " [");
            cm_buf_append(&disp, manifests.v[i].algo);
            cm_buf_putc(&disp, ']');
            free(rp);
            entries++;
            cm_count_inc(&entry_counts, manifests.v[i].algo);
            if(!cm_is_readable_file(target))
            {
                char *d = cm_buf_take(&disp);

                cm_reporter_status(&rep, "UNREAD", d);
                free(d);
                unread++;
                free(target);
                continue;
            }
            rc = cm_hash_with_provider(target, ai, p, &digest, 1);
            if(rc != 1 && g_interrupted)
            {
                cm_buf_free(&disp);
                free(digest);
                free(target);
                break;
            }
            else if(rc != 1)
            {
                char *d = cm_buf_take(&disp);

                cm_reporter_status(&rep, "ERROR", d);
                free(d);
                errors++;
                free(digest);
                free(target);
                continue;
            }
            if(cm_ascii_equal_ci(digest, rec.v[j].digest))
            {
                char *d = cm_buf_take(&disp);

                cm_reporter_status(&rep, "VALID", d);
                free(d);
                valid++;
            }
            else
            {
                char *d = cm_buf_take(&disp);

                cm_reporter_status(&rep, "INVALID", d);
                free(d);
                invalid++;
            }
            free(digest);
            free(target);
        }
        cm_rv_free(&rec);
    }

    if(g_interrupted)
    {
        cm_reporter_close(&rep);
        if(report_path)
        {
            cm_unlink(report_path);
            cm_registry_remove(&g_reserved_paths, report_path);
        }
        free(report_path);
        free(base);
        cm_mv_free(&manifests);
        cm_sv_free(&present);
        cm_pcv_free(&providers);
        cm_count_free(&entry_counts);
        return 1;
    }

    cm_reporter_line(&rep, "");
    cm_reporter_line(&rep, "Tools:");
    for(i = 0; i < providers.n; i++)
    {
        char line[256];

        snprintf(line, sizeof(line), "  %s: %s", providers.v[i].algo->name, cm_provider_name(providers.v[i].provider));
        cm_reporter_line(&rep, line);
    }

    cm_reporter_line(&rep, "");
    cm_reporter_line(&rep, "Entries:");
    {
        char line[128];
        size_t w = cm_entry_label_width(&present);

        for(i = 0; i < present.n; i++)
        {
            snprintf(line, sizeof(line), "  %-*s: %d", (int)w, present.v[i], cm_count_get(&entry_counts, present.v[i]));
            cm_reporter_line(&rep, line);
        }
        snprintf(line, sizeof(line), "  %-*s: %d", (int)w, "Total", entries);
        cm_reporter_line(&rep, line);
    }

    cm_reporter_line(&rep, "");
    cm_reporter_line(&rep, "Summary:");
    {
        char line[128];

        snprintf(line, sizeof(line), "  Manifests: %d", manicount);
        cm_reporter_line(&rep, line);
        snprintf(line, sizeof(line), "  Entries  : %d", entries);
        cm_reporter_line(&rep, line);
        snprintf(line, sizeof(line), "  Valid    : %d", valid);
        cm_reporter_line(&rep, line);
        snprintf(line, sizeof(line), "  Invalid  : %d", invalid);
        cm_reporter_line(&rep, line);
        snprintf(line, sizeof(line), "  Unread   : %d", unread);
        cm_reporter_line(&rep, line);
        snprintf(line, sizeof(line), "  Error    : %d", errors);
        cm_reporter_line(&rep, line);
    }

    cm_reporter_line(&rep, "");
    cm_reporter_line(&rep, "Operation complete.");
    if(!cm_reporter_close(&rep))
    {
        fprintf(stderr, "Error: failed to write check report output.\n");
        errors++;
        if(report_path)
        {
            cm_unlink(report_path);
            cm_registry_remove(&g_reserved_paths, report_path);
        }
    }
    else if(report_path)
    {
        cm_registry_remove(&g_reserved_paths, report_path);
        cm_print_output_path(report_path, NULL);
    }

    free(report_path);
    free(base);
    cm_mv_free(&manifests);
    cm_sv_free(&present);
    cm_pcv_free(&providers);
    cm_count_free(&entry_counts);

    return (invalid || unread || errors) ? 1 : 0;
}

typedef struct
{
    char *path;
    CmTimestamp ts;

#ifndef _WIN32
    dev_t dev;
    ino_t ino;
#endif
} CmDirTime;

typedef struct
{
    CmDirTime *v;
    size_t n, cap;
} CmDirTimeVec;

typedef struct
{
    CmStrVec files;
    CmStrVec directories;
} CmTimestampIssues;

static void cm_timestamp_issue(CmTimestampIssues *issues, int directory, const char *path)
{
    CmStrVec *v;
    char *n;

    if(!issues || !path)
        return;
    v = directory ? &issues->directories : &issues->files;
    n = cm_path_normalize(path);
    if(!cm_sv_contains(v, n))
        cm_sv_push(v, n);
    free(n);
}

static void cm_timestamp_issues_summary(const CmTimestampIssues *issues)
{
    if(issues && (issues->files.n || issues->directories.n))
        fprintf(stderr, "Warning: timestamp preservation incomplete (%lu file(s), %lu directory(s)).\n",
            (unsigned long)issues->files.n, (unsigned long)issues->directories.n);
}

static void cm_timestamp_issues_free(CmTimestampIssues *issues)
{
    if(!issues)
        return;
    cm_sv_free(&issues->files);
    cm_sv_free(&issues->directories);
}

static void cm_dtv_capture(CmDirTimeVec *v, CmTimestampIssues *issues, const char *dir)
{
    size_t i;
    CmFileInfo s;
    char *n = cm_path_real_existing(dir);

    for(i = 0; i < v->n; i++)
        if(strcmp(v->v[i].path, n) == 0)
        {
            free(n);
            return;
        }
    if(cm_file_info(n, 0, &s) != 0 || !s.is_dir)
    {
        cm_timestamp_issue(issues, 1, n);
        free(n);
        return;
    }

    if(v->n == v->cap)
    {
        size_t new_cap = v->cap ? cm_size_mul(v->cap, 2) : 16;

        v->v = (CmDirTime *)cm_xrealloc_array(v->v, new_cap, sizeof(CmDirTime));
        v->cap = new_cap;
    }

    v->v[v->n].path = n;
    v->v[v->n].ts = s.mtime;
#ifndef _WIN32
    v->v[v->n].dev = s.dev;
    v->v[v->n].ino = s.ino;
#endif
    v->n++;
}

static void cm_dtv_restore(CmDirTimeVec *v, CmTimestampIssues *issues)
{
    size_t i = v->n;

    while(i--)
    {
        CmFileInfo current;

        if(cm_file_info(v->v[i].path, 0, &current) != 0 || !current.is_dir || !current.mtime.valid)
        {
            cm_timestamp_issue(issues, 1, v->v[i].path);
            continue;
        }
#ifndef _WIN32
        if(current.dev != v->v[i].dev || current.ino != v->v[i].ino)
        {
            cm_timestamp_issue(issues, 1, v->v[i].path);
            continue;
        }
#endif
        if(current.mtime.sec == v->v[i].ts.sec && current.mtime.nsec == v->v[i].ts.nsec)
            continue;
        if(cm_set_mtime(v->v[i].path, v->v[i].ts) != 0)
            cm_timestamp_issue(issues, 1, v->v[i].path);
    }
}

static void cm_dtv_free(CmDirTimeVec *v)
{
    size_t i;

    for(i = 0; i < v->n; i++)
        free(v->v[i].path);
    free(v->v);
    memset(v, 0, sizeof(*v));
}

/* -------------------------------- derive ---------------------------------- */

static char *cm_manifest_stem(const char *manifest, const char *algo)
{
    char *base = cm_path_basename(manifest);
    const char *ext = cm_algo_ext(algo);
    size_t nb = strlen(base), ne = strlen(ext);
    char *r = NULL;

    if(nb > ne + 1 && base[nb - ne - 1] == '.' && cm_ends_ci(base, ext))
        r = cm_xstrndup(base, nb - ne - 1);
    free(base);

    return r;
}

static size_t cm_selector_order(const CmStrVec *order, const char *algo)
{
    size_t i;

    for(i = 0; i < order->n; ++i)
        if(strcmp(order->v[i], algo) == 0)
            return i;
    return order->n;
}

static int cm_derive_source_compare(const CmManifest *a, const CmManifest *b, const CmStrVec *order)
{
    char *ad = cm_path_dirname(a->path), *bd = cm_path_dirname(b->path);
    char *as = cm_manifest_stem(a->path, a->algo), *bs = cm_manifest_stem(b->path, b->algo);
    char *ab = cm_path_basename(a->path), *bb = cm_path_basename(b->path);
    int c = strcmp(ad, bd);

    if(!c)
        c = strcmp(as ? as : ab, bs ? bs : bb);
    if(!c)
    {
        size_t ao = cm_selector_order(order, a->algo), bo = cm_selector_order(order, b->algo);

        c = ao < bo ? -1 : (ao > bo ? 1 : 0);
    }

    if(!c)
        c = strcmp(ab, bb);
    free(ad);
    free(bd);
    free(as);
    free(bs);
    free(ab);
    free(bb);

    return c;
}

static void cm_sort_derive_sources(CmManifestVec *v, const CmStrVec *order)
{
    size_t i;

    for(i = 1; i < v->n; ++i)
    {
        CmManifest item = v->v[i];
        size_t j = i;

        while(j > 0 && cm_derive_source_compare(&v->v[j - 1], &item, order) > 0)
        {
            v->v[j] = v->v[j - 1];
            --j;
        }
        v->v[j] = item;
    }
}

static char *cm_derive_source_base(const char *path)
{
    return cm_generate_source_base(path);
}

static char *cm_derive_target_dir(const char *source, const char *source_base, const char *output_root)
{
    char *sd = cm_path_dirname(source);

    if(!output_root)
        return sd;
    {
        char *rel = cm_relative_path(source_base, sd), *r;

        if(strcmp(rel, ".") == 0)
        {
            r = cm_path_normalize(output_root);
        }
        else
        {
            char *tmp = cm_path_join(output_root, rel);

            r = cm_path_normalize(tmp);
            free(tmp);
        }
        free(rel);
        free(sd);
        return r;
    }
}

static char *cm_derive_intended(const char *source, const char *source_algo, const char *target_algo, const char *source_base, const char *output_root)
{
    char *stem = cm_manifest_stem(source, source_algo), *dir, *name, *r;
    CmBuf b;

    if(!stem)
        return NULL;
    dir = cm_derive_target_dir(source, source_base, output_root);
    cm_buf_init(&b);
    cm_buf_append(&b, stem);
    cm_buf_putc(&b, '.');
    cm_buf_append(&b, cm_algo_ext(target_algo));
    name = cm_buf_take(&b);
    r = cm_path_join(dir, name);
    {
        char *n = cm_path_normalize(r);

        free(r);
        r = n;
    }

    free(stem);
    free(dir);
    free(name);

    return r;
}

static int cm_derive_output_directory_is_safe(const char *root, const char *directory)
{
    char *r = cm_path_normalize(root), *d = cm_path_normalize(directory), *rel, *walk, *p;

    if(!cm_same_path_prefix(r, d))
    {
        free(r);
        free(d);
        return 0;
    }

    rel = cm_relative_path(r, d);
    if(strcmp(rel, ".") == 0)
    {
        free(r);
        free(d);
        free(rel);
        return 1;
    }

    walk = cm_xstrdup(r);
    p = rel;
    while(*p)
    {
        char *start = p, *seg, *next;
        CmFileInfo info;

        while(*p && !cm_is_sep(*p))
            p++;
        seg = cm_xstrndup(start, (size_t)(p - start));
        while(*p && cm_is_sep(*p))
            p++;
        if(!*seg || strcmp(seg, ".") == 0 || strcmp(seg, "..") == 0)
        {
            free(seg);
            continue;
        }
        next = cm_path_join(walk, seg);
        free(seg);
        free(walk);
        walk = next;
        if(cm_file_info(walk, 0, &info) != 0)
        {
            free(r);
            free(d);
            free(rel);
            free(walk);
            return 1;
        }
        if(info.is_symlink || !info.is_dir)
        {
            free(r);
            free(d);
            free(rel);
            free(walk);
            return 0;
        }
    }

    free(r);
    free(d);
    free(rel);
    free(walk);

    return 1;
}

static int cm_find_derive_peers(const char *source, const char *source_algo, const char *target_algo, const char *source_base, const char *output_root, CmStrVec *matches, int report_error)
{
    char *stem = cm_manifest_stem(source, source_algo), *dir;
    CmStrVec names = {0};
    size_t i;
    CmBuf sb;
    char *suffix;

    if(!stem)
        return 1;
    dir = cm_derive_target_dir(source, source_base, output_root);
    if(output_root && !cm_derive_output_directory_is_safe(output_root, dir))
    {
        if(report_error)
            fprintf(stderr, "Error: %s: target directory escapes through a symlink or invalid parent\n", cm_terminal_absolute_path_view(dir));
        free(stem);
        free(dir);
        return 0;
    }

    if(!cm_exists(dir))
    {
        free(stem);
        free(dir);
        return 1;
    }

    if(!cm_is_dir(dir) || cm_list_directory(dir, &names) != 0)
    {
        if(report_error)
            fprintf(stderr, "Error: %s: cannot scan target directory.\n", cm_terminal_absolute_path_view(dir));
        free(stem);
        free(dir);
        cm_sv_free(&names);
        return 0;
    }

    cm_buf_init(&sb);
    cm_buf_putc(&sb, '.');
    cm_buf_append(&sb, cm_algo_ext(target_algo));
    suffix = cm_buf_take(&sb);
    for(i = 0; i < names.n; i++)
    {
        size_t ns = strlen(names.v[i]), st = strlen(stem), su = strlen(suffix);

        if(ns == st + su && memcmp(names.v[i], stem, st) == 0 && cm_ends_ci(names.v[i], suffix))
        {
            char *p = cm_path_join(dir, names.v[i]);

            cm_sv_push(matches, p);
            free(p);
        }
    }

    if(matches->n > 1)
        qsort(matches->v, matches->n, sizeof(char *), cm_byte_compare_qsort);
    free(suffix);
    free(stem);
    free(dir);
    cm_sv_free(&names);

    return 1;
}

static char *cm_derive_key(const char *manifest, const char *entry, const char *mode, int compare_text)
{
    char *native = cm_manifest_path_to_native(entry, mode, 1), *r;

    if(compare_text)
    {
        r = cm_render_native_path(native, mode, entry);
        free(native);
        return r;
    }

    if(cm_path_is_abs(native))
    {
        r = cm_path_normalize(native);
    }
    else
    {
        char *d = cm_path_dirname(manifest), *j = cm_path_join(d, native);

        r = cm_path_normalize(j);
        free(d);
        free(j);
    }

    free(native);

    return r;
}

static char *cm_derive_output_name(const char *entry, const char *mode)
{
    char *native = cm_manifest_path_to_native(entry, mode, 1), *out = cm_path_for_manifest_output(native, mode, entry);

    free(native);

    return out;
}

static int cm_record_name_natural_qsort(const void *aa, const void *bb)
{
    const CmRecord *a = (const CmRecord *)aa, *b = (const CmRecord *)bb;

    return cm_natural_compare_str(a->name, b->name);
}

static int cm_record_name_lex_qsort(const void *aa, const void *bb)
{
    const CmRecord *a = (const CmRecord *)aa, *b = (const CmRecord *)bb;

    return strcmp(a->name, b->name);
}

static int cm_target_counts(const char *manifest, const char *algo, const CmOptions *o, int compare_text, CmCountMap *counts)
{
    CmRecordVec rec = {0};
    size_t i;
    int vc = 0, hn = 0;

    if(!cm_read_records(manifest, algo, &rec, &vc, &hn))
    {
        cm_rv_free(&rec);
        return 0;
    }

    for(i = 0; i < rec.n; i++)
    {
        char *k = cm_derive_key(manifest, rec.v[i].name, o->path_separator, compare_text);

        cm_count_inc(counts, k);
        free(k);
    }

    cm_rv_free(&rec);

    return 1;
}

/* Existing derive targets are compared as path-occurrence multisets; their digests and data files are not rehashed. */
static int cm_compare_derive_existing(const char *source_manifest, const char *target_manifest, const char *target_algo, const CmRecordVec *entries, const CmOptions *o, int *missing_total, int *present_total, int *complete, int *incomplete)
{
    CmCountMap counts = {0};
    size_t k;
    int miss = 0, expected = (int)entries->n;

    if(!cm_is_file(target_manifest) || !cm_target_counts(target_manifest, target_algo, o, o->output != NULL, &counts))
    {
        cm_count_free(&counts);
        return 0;
    }

    for(k = 0; k < entries->n; ++k)
    {
        char *key = cm_derive_key(source_manifest, entries->v[k].name, o->path_separator, o->output != NULL);
        size_t q;
        int found = 0;

        for(q = 0; q < counts.n; ++q)
            if(strcmp(counts.v[q].key, key) == 0 && counts.v[q].count > 0)
            {
                counts.v[q].count--;
                found = 1;
                break;
            }
        if(!found)
        {
            CmBuf message;
            char *text;
            char *target_display = cm_path_normalize(target_manifest);

            cm_buf_init(&message);
            cm_buf_append(&message, entries->v[k].name);
            cm_buf_append(&message, " [");
            cm_buf_append(&message, target_algo);
            cm_buf_append(&message, "] in ");
            cm_buf_append(&message, target_display);
            text = cm_buf_take(&message);
            cm_derive_status("MISSING", text);
            free(text);
            free(target_display);
            ++miss;
            ++*missing_total;
        }
        free(key);
    }

    {
        CmBuf message;
        char count_text[96];
        char *text;
        char *target_display = cm_path_normalize(target_manifest);
        char *source_display = cm_path_normalize(source_manifest);

        snprintf(count_text, sizeof(count_text), " (%s: %d/%d; ref: ", target_algo, expected - miss, expected);
        cm_buf_init(&message);
        cm_buf_append(&message, target_display);
        cm_buf_append(&message, count_text);
        cm_buf_append(&message, source_display);
        cm_buf_putc(&message, ')');
        text = cm_buf_take(&message);
        if(miss)
        {
            cm_derive_status("INCOMPLETE", text);
            ++*incomplete;
        }
        else
        {
            cm_derive_status("COMPLETE", text);
            ++*complete;
        }
        free(text);
        free(target_display);
        free(source_display);
    }

    *present_total += expected - miss;
    cm_count_free(&counts);

    return 1;
}

static int cm_reserve_exact(const char *path)
{
    char *d = cm_path_dirname(path);

    if(!cm_is_dir(d) && cm_make_dirs(d) != 0)
    {
        free(d);
        return 0;
    }

    free(d);
    if(cm_reserve_exclusive(path) != 0)
        return 0;
    cm_sv_push(&g_reserved_paths, path);

    return 1;
}

static int cm_mode_derive(const CmOptions *o)
{
    CmManifestVec src = {0};
    CmDirTimeVec dirs = {0};
    CmTimestampIssues timestamp_issues = {0};
    CmCountMap source_entry_counts = {0}, target_entry_counts = {0};
    char *source_base, *outroot = NULL;
    size_t i, j, k;
    CmStrVec needed = {0}, used_tools = {0};
    CmProviderChoiceVec providers = {0};
    int scan_errors = 0, errors = 0, source_valid = 0, source_failed = 0, source_entries = 0, missing_total = 0, present_entries = 0, created_entries = 0, failed_entries = 0, created = 0, complete = 0, incomplete = 0, failed_targets = 0;

    cm_collect_manifests(o->path, o->recursive, &o->source_algorithms, 0, &src);
    scan_errors = g_scan_errors;
    errors += scan_errors;
    if(!src.n)
    {
        fprintf(stderr, "Error: no selected reference checksum manifest files found in: %s\n", cm_terminal_path_view(o->path));
        cm_mv_free(&src);
        return 1;
    }

    source_base = cm_derive_source_base(o->path);
    if(o->output)
    {
        outroot = cm_path_normalize(o->output);
        if(cm_exists(outroot) && !cm_is_dir(outroot))
        {
            fprintf(stderr, "Error: derive --output must name a directory\n");
            free(outroot);
            free(source_base);
            cm_mv_free(&src);
            return 2;
        }
        if(!cm_is_dir(outroot) && cm_make_dirs(outroot) != 0)
        {
            fprintf(stderr, "Error: cannot create derive output directory: %s\n", cm_terminal_path_view(outroot));
            free(outroot);
            free(source_base);
            cm_mv_free(&src);
            return 2;
        }
    }

    cm_sort_derive_sources(&src, &o->source_algorithms);
    /* Preflight only algorithms that have at least one missing target. */
    for(i = 0; i < src.n; i++)
        for(j = 0; j < o->algorithms.n; j++)
        {
            CmStrVec peers = {0};

            if(cm_find_derive_peers(src.v[i].path, src.v[i].algo, o->algorithms.v[j], source_base, outroot, &peers, 1) && peers.n == 0 && !cm_sv_contains(&needed, o->algorithms.v[j]))
                cm_sv_push(&needed, o->algorithms.v[j]);
            cm_sv_free(&peers);
        }
    if(needed.n && !cm_prepare_providers(&needed, &o->tools, &providers))
    {
        cm_pcv_free(&providers);
        cm_sv_free(&needed);
        free(outroot);
        free(source_base);
        cm_mv_free(&src);
        return 127;
    }

    for(i = 0; i < src.n; i++)
    {
        CmRecordVec entries = {0};

        if(g_interrupted)
            break;

        int vc = 0, hn = 0;
        CmFileInfo srcinfo;

        memset(&srcinfo, 0, sizeof(srcinfo));
        if(!cm_read_records(src.v[i].path, src.v[i].algo, &entries, &vc, &hn))
        {
            fprintf(stderr, "Error: %s: cannot open reference manifest\n", cm_terminal_absolute_path_view(src.v[i].path));
            errors++;
            source_failed++;
            continue;
        }
        if(!vc)
        {
            fprintf(stderr, "Error: %s: no valid checksum entries\n", cm_terminal_absolute_path_view(src.v[i].path));
            errors++;
            source_failed++;
            cm_rv_free(&entries);
            continue;
        }
        source_valid++;
        source_entries += (int)entries.n;
        cm_count_add(&source_entry_counts, src.v[i].algo, (int)entries.n);
        for(j = 0; j < o->algorithms.n; j++)
            cm_count_add(&target_entry_counts, o->algorithms.v[j], (int)entries.n);
        if(o->natural_sort && entries.n > 1)
            qsort(entries.v, entries.n, sizeof(CmRecord), cm_record_name_natural_qsort);
        else if(o->lexicographic_sort && entries.n > 1)
            qsort(entries.v, entries.n, sizeof(CmRecord), cm_record_name_lex_qsort);
        if(cm_file_info(src.v[i].path, 1, &srcinfo) != 0)
            memset(&srcinfo, 0, sizeof(srcinfo));
        for(j = 0; j < o->algorithms.n; j++)
        {
            const char *target_algo;
            CmStrVec peers = {0};
            char *intended;

            if(g_interrupted)
                break;
            target_algo = o->algorithms.v[j];
            if(!cm_find_derive_peers(src.v[i].path, src.v[i].algo, target_algo, source_base, outroot, &peers, 0))
            {
                fprintf(stderr, "Error: %s [%s]: cannot scan target directory\n", cm_terminal_absolute_path_view(src.v[i].path), target_algo);
                errors++;
                failed_targets++;
                failed_entries += (int)entries.n;
                cm_sv_free(&peers);
                continue;
            }
            if(peers.n > 1)
            {
                fprintf(stderr, "Error: %s [%s]: multiple case-variant target manifests exist\n", cm_terminal_absolute_path_view(src.v[i].path), target_algo);
                errors++;
                failed_targets++;
                failed_entries += (int)entries.n;
                cm_sv_free(&peers);
                continue;
            }
            if(peers.n == 1)
            {
                if(!cm_compare_derive_existing(src.v[i].path, peers.v[0], target_algo, &entries, o, &missing_total, &present_entries, &complete, &incomplete))
                {
                    fprintf(stderr, "Error: %s: cannot open target manifest\n", cm_terminal_absolute_path_view(peers.v[0]));
                    errors++;
                    failed_targets++;
                    failed_entries += (int)entries.n;
                }
                cm_sv_free(&peers);
                continue;
            }
            cm_sv_free(&peers);
            intended = cm_derive_intended(src.v[i].path, src.v[i].algo, target_algo, source_base, outroot);
            if(!intended)
            {
                errors++;
                failed_targets++;
                failed_entries += (int)entries.n;
                continue;
            }
            if(outroot && !cm_secure_prepare_parent(outroot, intended))
            {
                fprintf(stderr, "Error: %s: output path escapes through a symlink or invalid parent\n", cm_terminal_path_view(intended));
                free(intended);
                errors++;
                failed_targets++;
                failed_entries += (int)entries.n;
                continue;
            }
            else
            {
                char *d = cm_path_dirname(intended);

                if(!cm_is_dir(d) && cm_make_dirs(d) != 0)
                {
                    fprintf(stderr, "Error: %s: cannot create target directory\n", cm_terminal_path_view(d));
                    free(d);
                    free(intended);
                    errors++;
                    failed_targets++;
                    failed_entries += (int)entries.n;
                    continue;
                }
                free(d);
            }
            if(!o->update_timestamp)
            {
                char *d = cm_path_dirname(intended);

                cm_dtv_capture(&dirs, &timestamp_issues, d);
                free(d);
            }
            /* Recheck peers to close the planning/commit race.  A single regular
             * target that appeared is compared immediately, exactly like an
             * originally-existing target; ambiguous/non-regular peers fail. */
            {
                CmStrVec late = {0};

                if(!cm_find_derive_peers(src.v[i].path, src.v[i].algo, target_algo, source_base, outroot, &late, 1))
                {
                    cm_sv_free(&late);
                    free(intended);
                    errors++;
                    failed_targets++;
                    failed_entries += (int)entries.n;
                    continue;
                }
                if(late.n)
                {
                    if(late.n != 1 || !cm_is_file(late.v[0]))
                    {
                        fprintf(stderr, "Error: %s [%s]: target became ambiguous or non-regular before creation\n", cm_terminal_absolute_path_view(src.v[i].path), target_algo);
                        errors++;
                        failed_targets++;
                        failed_entries += (int)entries.n;
                    }
                    else if(!cm_compare_derive_existing(src.v[i].path, late.v[0], target_algo, &entries, o, &missing_total, &present_entries, &complete, &incomplete))
                    {
                        fprintf(stderr, "Error: %s: cannot open target manifest\n", cm_terminal_absolute_path_view(late.v[0]));
                        errors++;
                        failed_targets++;
                        failed_entries += (int)entries.n;
                    }
                    cm_sv_free(&late);
                    free(intended);
                    continue;
                }
                cm_sv_free(&late);
            }
            {
                CmRecordVec outrec = {0};
                int fail = 0;
                CmProvider p = cm_choice_for(&providers, target_algo);
                const CmAlgorithmInfo *ai = cm_find_algo(target_algo);

                for(k = 0; k < entries.n; k++)
                {
                    char *outname, *target, *digest = NULL;

                    if(g_interrupted)
                    {
                        fail = 1;
                        break;
                    }
                    outname = cm_derive_output_name(entries.v[k].name, o->path_separator);
                    target = cm_entry_target(src.v[i].path, entries.v[k].name, o->path_separator, 0, 1);
                    if(!outname)
                    {
                        fprintf(stderr, "Error: %s: cannot represent entry path with selected path separator\n", cm_terminal_path_view(entries.v[k].name));
                        fail = 1;
                        errors++;
                        free(target);
                        continue;
                    }
                    if(!cm_is_readable_file(target))
                    {
                        {
                            const char *source_display = cm_terminal_absolute_path_view(src.v[i].path);
                            const char *entry_display = cm_terminal_path_view(entries.v[k].name);

                            fprintf(stderr, "Error: %s:%zu: referenced file is missing, not regular, or unreadable: %s\n", source_display, entries.v[k].line_no, entry_display);
                        }
                        fail = 1;
                        errors++;
                        free(outname);
                        free(target);
                        continue;
                    }
                    if(!cm_sv_contains(&used_tools, target_algo))
                        cm_sv_push(&used_tools, target_algo);
                    if(cm_hash_with_provider(target, ai, p, &digest, 1) != 1)
                    {
                        if(!g_interrupted)
                        {
                            {
                                const char *source_display = cm_terminal_absolute_path_view(src.v[i].path);
                                const char *entry_display = cm_terminal_path_view(entries.v[k].name);

                                fprintf(stderr, "Error: %s:%zu: failed to calculate %s checksum for %s\n", source_display, entries.v[k].line_no, target_algo, entry_display);
                            }
                            errors++;
                        }
                        fail = 1;
                        free(outname);
                        free(target);
                        free(digest);
                        if(g_interrupted)
                            break;
                        continue;
                    }
                    cm_add_record(&outrec, digest, outname);
                    free(digest);
                    free(outname);
                    free(target);
                }
                if(fail || outrec.n != entries.n)
                {
                    failed_targets++;
                    failed_entries += (int)entries.n;
                    cm_rv_free(&outrec);
                    free(intended);
                    continue;
                }
                if(!cm_reserve_exact(intended))
                {
                    fprintf(stderr, "Error: %s: target appeared or could not be reserved before creation\n", cm_terminal_path_view(intended));
                    errors++;
                    failed_targets++;
                    failed_entries += (int)entries.n;
                    cm_rv_free(&outrec);
                    free(intended);
                    continue;
                }
                if(cm_write_records(intended, target_algo, &outrec, o))
                {
                    if(!o->update_timestamp && (!srcinfo.mtime.valid || cm_set_mtime(intended, srcinfo.mtime) != 0))
                        cm_timestamp_issue(&timestamp_issues, 0, intended);
                    {
                        CmBuf message;
                        char details[96];
                        char *text;
                        char *source_display = cm_path_normalize(src.v[i].path);

                        snprintf(details, sizeof(details), " (%s: %lu entries; ref: ", target_algo, (unsigned long)outrec.n);
                        cm_buf_init(&message);
                        cm_buf_append(&message, intended);
                        cm_buf_append(&message, details);
                        cm_buf_append(&message, source_display);
                        cm_buf_putc(&message, ')');
                        text = cm_buf_take(&message);
                        cm_derive_status("OUTPUT", text);
                        free(text);
                        free(source_display);
                    }
                    created++;
                    created_entries += (int)entries.n;
                }
                else
                {
                    cm_unlink(intended);
                    cm_registry_remove(&g_reserved_paths, intended);
                    errors++;
                    failed_targets++;
                    failed_entries += (int)entries.n;
                }
                cm_rv_free(&outrec);
                free(intended);
            }
        }
        cm_rv_free(&entries);
    }

    if(g_interrupted)
    {
        if(!o->update_timestamp)
            cm_dtv_restore(&dirs, &timestamp_issues);
        cm_timestamp_issues_summary(&timestamp_issues);
        cm_dtv_free(&dirs);
        cm_timestamp_issues_free(&timestamp_issues);
        cm_count_free(&source_entry_counts);
        cm_count_free(&target_entry_counts);
        cm_sv_free(&used_tools);
        cm_pcv_free(&providers);
        cm_sv_free(&needed);
        free(outroot);
        free(source_base);
        cm_mv_free(&src);
        return 1;
    }

    printf("\n");
    if(used_tools.n)
    {
        printf("Tools:\n");
        for(i = 0; i < o->algorithms.n; i++)
            if(cm_sv_contains(&used_tools, o->algorithms.v[i]))
                printf("  %s: %s\n", o->algorithms.v[i], cm_provider_name(cm_choice_for(&providers, o->algorithms.v[i])));
        printf("\n");
    }

    printf("Entries:\n  Reference:\n");
    {
        size_t w = cm_entry_label_width(&o->source_algorithms);
        int total = 0;

        for(i = 0; i < o->source_algorithms.n; i++)
        {
            int n = cm_count_get(&source_entry_counts, o->source_algorithms.v[i]);

            total += n;
            printf("    %-*s: %d\n", (int)w, o->source_algorithms.v[i], n);
        }
        printf("    %-*s: %d\n", (int)w, "Total", total);
    }

    printf("\n  Target:\n");
    {
        size_t w = cm_entry_label_width(&o->algorithms);
        int total = 0;

        for(i = 0; i < o->algorithms.n; i++)
        {
            int n = cm_count_get(&target_entry_counts, o->algorithms.v[i]);

            total += n;
            printf("    %-*s: %d\n", (int)w, o->algorithms.v[i], n);
        }
        printf("    %-*s: %d\n", (int)w, "Total", total);
    }

    printf("\nSummary:\n"
        "  References:\n"
        "    Valid : %d\n"
        "    Failed: %d\n"
        "\n"
        "  Reference entries:\n"
        "    Total: %d\n"
        "\n"
        "  Targets:\n"
        "    Complete  : %d\n"
        "    Created   : %d\n"
        "    Incomplete: %d\n"
        "    Failed    : %d\n"
        "\n"
        "  Target entries:\n"
        "    Present: %d\n"
        "    Created: %d\n"
        "    Missing: %d\n"
        "    Failed : %d\n"
        "    Total  : %d\n"
        "\n"
        "  Failures:\n"
        "    Scan     : %d\n"
        "    Reference: %d\n"
        "    Target   : %d\n"
        "\n"
        "Operation complete.\n",
        source_valid, source_failed, source_entries, complete, created, incomplete, failed_targets, present_entries,
        created_entries, missing_total, failed_entries, present_entries + created_entries + missing_total + failed_entries,
        scan_errors, source_failed, failed_targets);
    if(!o->update_timestamp)
        cm_dtv_restore(&dirs, &timestamp_issues);
    cm_timestamp_issues_summary(&timestamp_issues);
    cm_dtv_free(&dirs);
    cm_timestamp_issues_free(&timestamp_issues);
    cm_count_free(&source_entry_counts);
    cm_count_free(&target_entry_counts);
    cm_sv_free(&used_tools);
    cm_pcv_free(&providers);
    cm_sv_free(&needed);
    free(outroot);
    free(source_base);
    cm_mv_free(&src);

    return (missing_total || errors) ? 1 : 0;
}

/* ------------------------------- format ----------------------------------- */

static int cm_read_all(const char *path, unsigned char **data, size_t *len)
{
    FILE *f = cm_fopen(path, "rb");
    CmBuf b;
    unsigned char tmp[65536];
    size_t n;

    if(!f)
        return 0;
    cm_buf_init(&b);
    while((n = fread(tmp, 1, sizeof(tmp), f)) > 0)
    {
        if(g_interrupted)
        {
            cm_buf_free(&b);
            fclose(f);
            return 0;
        }
        cm_buf_append_n(&b, (const char *)tmp, n);
    }

    if(ferror(f))
    {
        cm_buf_free(&b);
        fclose(f);
        return 0;
    }

    fclose(f);
    *len = b.len;
    *data = (unsigned char *)cm_buf_take(&b);

    return 1;
}

static int cm_copy_file(const char *src, const char *dst, unsigned long mode, CmTimestamp ts, int preserve_time, CmTimestampIssues *issues)
{
    FILE *a = cm_fopen(src, "rb"), *b;
    unsigned char buf[65536];
    size_t n;

    if(!a)
        return 0;
    b = cm_fopen(dst, "wb");
    if(!b)
    {
        fclose(a);
        return 0;
    }
    while((n = fread(buf, 1, sizeof(buf), a)) > 0)
        if(g_interrupted || fwrite(buf, 1, n, b) != n)
        {
            fclose(a);
            fclose(b);
            return 0;
        }
    if(ferror(a) || fflush(b) != 0 || g_interrupted)
    {
        fclose(a);
        fclose(b);
        return 0;
    }
#ifndef _WIN32
    if(fsync(fileno(b)) != 0)
    {
        fclose(a);
        fclose(b);
        return 0;
    }
#endif
    fclose(a);
    fclose(b);
    if(cm_set_file_mode(dst, mode) != 0)
        return 0;
    if(preserve_time && cm_set_mtime(dst, ts) != 0)
        cm_timestamp_issue(issues, 0, dst);

    return 1;
}

static char *cm_reserve_backup(const char *manifest)
{
    CmBuf b;
    char *desired, *dir, *base;
    int r;

    cm_buf_init(&b);
    cm_buf_append(&b, manifest);
    cm_buf_append(&b, ".cmbak");
    desired = cm_buf_take(&b);
    r = cm_reserve_exclusive(desired);
    if(r == 0)
    {
        cm_sv_push(&g_reserved_paths, desired);
        return desired;
    }

    if(r != 1)
    {
        free(desired);
        return NULL;
    }

    free(desired);
    dir = cm_path_dirname(manifest);
    base = cm_path_basename(manifest);
    for(;;)
    {
        char hex[9];
        char *name, *p;

        cm_random_hex(hex);
        cm_buf_init(&b);
        cm_buf_append(&b, base);
        cm_buf_putc(&b, '-');
        cm_buf_append(&b, hex);
        cm_buf_append(&b, ".cmbak");
        name = cm_buf_take(&b);
        p = cm_path_join(dir, name);
        free(name);
        r = cm_reserve_exclusive(p);
        if(r == 0)
        {
            cm_sv_push(&g_reserved_paths, p);
            free(dir);
            free(base);
            return p;
        }
        free(p);
        if(r != 1)
        {
            free(dir);
            free(base);
            return NULL;
        }
    }
}

static char *cm_format_filename(const char *name, const char *mode)
{
    char *native, *p, *out;

    if(cm_ascii_equal_ci(mode, "default"))
        return cm_xstrdup(name);
    native = cm_xstrdup(name);
    for(p = native; *p; p++)
        if(*p == '/' || *p == '\\')
            *p = CM_SEP;
    out = cm_path_for_manifest_output(native, mode, name);
    free(native);

    return out;
}

/* Rewrite a manifest through a sibling temporary file, then replace the destination in one commit step. */
static int cm_atomic_write_bytes(const char *path, const unsigned char *data, size_t len, unsigned long mode, CmTimestamp ts, int preserve_time, CmTimestampIssues *issues)
{
    char *dir = cm_path_dirname(path), *tmp = cm_temp_in_dir(dir);
    FILE *f;

    free(dir);
    if(!tmp)
        return 0;
    f = cm_fopen(tmp, "wb");
    if(!f)
    {
        cm_unlink(tmp);
        cm_registry_remove(&g_temp_paths, tmp);
        free(tmp);
        return 0;
    }

    if(len && fwrite(data, 1, len, f) != len)
    {
        fclose(f);
        cm_unlink(tmp);
        cm_registry_remove(&g_temp_paths, tmp);
        free(tmp);
        return 0;
    }

    if(fflush(f) != 0)
    {
        fclose(f);
        cm_unlink(tmp);
        cm_registry_remove(&g_temp_paths, tmp);
        free(tmp);
        return 0;
    }
#ifndef _WIN32
    if(fsync(fileno(f)) != 0)
    {
        fclose(f);
        cm_unlink(tmp);
        cm_registry_remove(&g_temp_paths, tmp);
        free(tmp);
        return 0;
    }
#endif
    fclose(f);
    if(cm_set_file_mode(tmp, mode) != 0)
    {
        cm_unlink(tmp);
        cm_registry_remove(&g_temp_paths, tmp);
        free(tmp);
        return 0;
    }

    if(preserve_time && cm_set_mtime(tmp, ts) != 0)
        cm_timestamp_issue(issues, 0, path);
    if(g_interrupted)
    {
        cm_unlink(tmp);
        cm_registry_remove(&g_temp_paths, tmp);
        free(tmp);
        return 0;
    }

    if(cm_rename(tmp, path) != 0)
    {
        cm_unlink(tmp);
        cm_registry_remove(&g_temp_paths, tmp);
        free(tmp);
        return 0;
    }

    cm_registry_remove(&g_temp_paths, tmp);
    free(tmp);
#ifdef _WIN32
    if(preserve_time && cm_set_mtime(path, ts) != 0)
        cm_timestamp_issue(issues, 0, path);
#endif
    return 1;
}

static int cm_stdin_is_tty()
{
#ifdef _WIN32
    return _isatty(_fileno(stdin)) != 0;
#else
    return isatty(fileno(stdin)) != 0;
#endif
}

static char *cm_extensions_description(const CmStrVec *algorithms)
{
    CmStrVec seen = {0};
    CmBuf out;
    size_t i;

    cm_buf_init(&out);
    for(i = 0; i < algorithms->n; i++)
    {
        const char *extension = cm_algo_ext(algorithms->v[i]);
        CmBuf item;
        char *value;

        cm_buf_init(&item);
        cm_buf_putc(&item, '.');
        cm_buf_append(&item, extension);
        value = cm_buf_take(&item);
        if(cm_sv_contains(&seen, value))
        {
            free(value);
            continue;
        }
        if(seen.n)
            cm_buf_putc(&out, ',');
        cm_buf_append(&out, value);
        cm_sv_push(&seen, value);
        free(value);
    }

    cm_sv_free(&seen);
    cm_buf_append(&out, " (case-insensitive)");

    return cm_buf_take(&out);
}

static const char *cm_delimiter_description(const CmStrVec *algorithms, const char *delimiter)
{
    size_t i;
    int has_filename_first = 0, has_digest_first = 0;
    int asterisk = delimiter && strcmp(delimiter, " *") == 0;

    for(i = 0; i < algorithms->n; i++)
    {
        const CmAlgorithmInfo *info = cm_find_algo(algorithms->v[i]);

        if(info && info->style == CM_FILENAME_FIRST)
            has_filename_first = 1;
        else
            has_digest_first = 1;
    }

    if(has_filename_first && has_digest_first)
        return asterisk ? "hash: \" *\"; CRC: one space" : "hash: two spaces; CRC: one space";
    if(has_filename_first)
        return "one space";

    return asterisk ? "\" *\"" : "two spaces";
}

static int cm_prompt_yes(const char *prompt, int exact)
{
    char buf[128];
    size_t n;

    printf("%s", prompt);
    fflush(stdout);
    if(!fgets(buf, sizeof(buf), stdin))
    {
        if(g_interrupted)
            return 0;
        printf("\n");
        return 0;
    }

    n = strlen(buf);
    while(n && (buf[n - 1] == '\n' || buf[n - 1] == '\r'))
        buf[--n] = 0;
    if(!cm_stdin_is_tty())
        printf("\n");
    if(exact)
        return strcmp(buf, "yes") == 0;

    return cm_ascii_equal_ci(buf, "y") || cm_ascii_equal_ci(buf, "yes");
}

static int cm_mode_format(const CmOptions *o)
{
    CmManifestVec mv = {0};
    CmDirTimeVec dirs = {0};
    CmTimestampIssues timestamp_issues = {0};
    CmCountMap entry_counts = {0};
    CmStrVec present = {0};
    size_t i, j;
    int errors = 0, updated = 0, unchanged = 0, backups = 0, entries = 0;
    char *plan = cm_path_normalize(o->path);

    {
        char *extensions = cm_extensions_description(&o->algorithms);

        printf("Format plan:\n  Path               : %s\n  Algorithms         : ", cm_terminal_path_view(plan));
        for(i = 0; i < o->algorithms.n; i++)
            printf("%s%s", i ? "," : "", o->algorithms.v[i]);
        printf("\n"
            "  Extensions         : %s\n"
            "  Recursive          : %s\n"
            "  Delimiter          : %s\n"
            "  Newline            : %s\n"
            "  Path separator     : %s\n"
            "  File mtime         : %s\n"
            "  Directory mtime    : %s\n"
            "  Backup             : %s\n"
            "  Digest values      : preserved\n"
            "  Non-entry lines    : preserved\n"
            "\n",
            extensions, o->recursive ? "yes" : "no", cm_delimiter_description(&o->algorithms, o->delimiter), o->newline_mode,
            o->path_separator, o->update_timestamp ? "no (-T)" : "yes (best effort)",
            o->update_timestamp ? "no (-T)" : "yes (best effort)", o->backup ? "yes (.cmbak)" : "no");
        free(extensions);
    }

    free(plan);
    if(!cm_prompt_yes("Proceed? [y/N]: ", 0))
    {
        if(g_interrupted)
            return 1;
        printf("\nCancelled.\n");
        return 0;
    }

    printf("\n");
    cm_collect_manifests(o->path, o->recursive, &o->algorithms, 0, &mv);
    errors += g_scan_errors;
    if(!mv.n)
    {
        fprintf(stderr, "Error: no selected checksum manifest files found in: %s\n", cm_terminal_path_view(o->path));
        cm_mv_free(&mv);
        return 1;
    }

    if(!o->update_timestamp)
        for(i = 0; i < mv.n; i++)
        {
            char *d = cm_path_dirname(mv.v[i].path);

            cm_dtv_capture(&dirs, &timestamp_issues, d);
            free(d);
        }
    for(i = 0; i < mv.n; i++)
    {
        unsigned char *original = NULL;

        if(g_interrupted)
            break;

        size_t olen = 0;
        CmFileInfo st;
        CmStrVec lines = {0};
        int hn = 0, format_failed = 0;
        CmBuf rendered;
        const char *nl = cm_newline_bytes(o->newline_mode);

        if(cm_is_symlink(mv.v[i].path))
        {
            fprintf(stderr, "Error: %s: symbolic-link manifests are not rewritten\n", cm_terminal_path_view(mv.v[i].path));
            errors++;
            continue;
        }
        if(cm_file_info(mv.v[i].path, 1, &st) != 0 || !cm_read_all(mv.v[i].path, &original, &olen) || memchr(original, 0, olen))
        {
            fprintf(stderr, "Error: %s: cannot safely read manifest%s\n", cm_terminal_path_view(mv.v[i].path), original && memchr(original, 0, olen) ? " (contains NUL)" : "");
            free(original);
            errors++;
            continue;
        }
        if(cm_read_lines(mv.v[i].path, &lines, &hn) != 0)
        {
            free(original);
            cm_sv_free(&lines);
            errors++;
            continue;
        }
        cm_buf_init(&rendered);
        for(j = 0; j < lines.n; j++)
        {
            CmRecord r;

            if(cm_parse_manifest_line(mv.v[i].algo, lines.v[j], &r))
            {
                char *line, *name;

                if(cm_ascii_equal_ci(o->path_separator, "default"))
                {
                    line = cm_format_record_preserving_name(mv.v[i].algo, r.digest, r.raw_name, o->delimiter, r.escaped);
                }
                else
                {
                    name = cm_format_filename(r.name, o->path_separator);
                    if(!name)
                    {
                        cm_record_free(&r);
                        errors++;
                        format_failed = 1;
                        break;
                    }
                    line = cm_format_record(mv.v[i].algo, r.digest, name, o->delimiter);
                    if(r.escaped && line[0] != '\\')
                    {
                        CmBuf q;
                        char *t;

                        cm_buf_init(&q);
                        cm_buf_putc(&q, '\\');
                        cm_buf_append(&q, line);
                        t = cm_buf_take(&q);
                        free(line);
                        line = t;
                    }
                    free(name);
                }
                cm_buf_append(&rendered, line);
                cm_buf_append(&rendered, nl);
                free(line);
                entries++;
                cm_count_inc(&entry_counts, mv.v[i].algo);
                cm_record_free(&r);
            }
            else
            {
                cm_buf_append(&rendered, lines.v[j]);
                cm_buf_append(&rendered, nl);
            }
        }
        if(format_failed)
        {
            free(original);
            cm_sv_free(&lines);
            cm_buf_free(&rendered);
            continue;
        }
        if(o->backup)
        {
            char *bp = cm_reserve_backup(mv.v[i].path);

            if(!bp || !cm_copy_file(mv.v[i].path, bp, st.mode, st.mtime, !o->update_timestamp, &timestamp_issues))
            {
                fprintf(stderr, "Error: %s: cannot create backup.\n", cm_terminal_path_view(mv.v[i].path));
                if(bp)
                {
                    cm_unlink(bp);
                    cm_registry_remove(&g_reserved_paths, bp);
                }
                free(bp);
                free(original);
                cm_sv_free(&lines);
                cm_buf_free(&rendered);
                errors++;
                continue;
            }
            cm_registry_remove(&g_reserved_paths, bp);
            {
                char *backup_display = cm_path_normalize(bp);

                cm_format_status("BACKUP", backup_display);
                free(backup_display);
            }
            backups++;
            free(bp);
        }
        if(olen == rendered.len && (olen == 0 || memcmp(original, rendered.data, olen) == 0))
        {
            if(!o->update_timestamp)
            {
                int same = cm_path_mtime_matches(mv.v[i].path, st.mtime, 0);

                if(same < 0 || (!same && cm_set_mtime(mv.v[i].path, st.mtime) != 0))
                    cm_timestamp_issue(&timestamp_issues, 0, mv.v[i].path);
            }
            cm_format_status("UNCHANGED", mv.v[i].path);
            unchanged++;
        }
        else if(cm_atomic_write_bytes(mv.v[i].path, (unsigned char *)(rendered.data ? rendered.data : ""), rendered.len, st.mode, st.mtime, !o->update_timestamp, &timestamp_issues))
        {
            cm_format_status("UPDATED", mv.v[i].path);
            updated++;
        }
        else
        {
            fprintf(stderr, "Error: %s: cannot rewrite manifest.\n", cm_terminal_path_view(mv.v[i].path));
            errors++;
        }
        free(original);
        cm_sv_free(&lines);
        cm_buf_free(&rendered);
    }

    if(!o->update_timestamp)
        cm_dtv_restore(&dirs, &timestamp_issues);
    if(g_interrupted)
    {
        cm_timestamp_issues_summary(&timestamp_issues);
        cm_sv_free(&present);
        cm_count_free(&entry_counts);
        cm_dtv_free(&dirs);
        cm_timestamp_issues_free(&timestamp_issues);
        cm_mv_free(&mv);
        return 1;
    }

    for(i = 0; i < o->algorithms.n; i++)
        for(j = 0; j < mv.n; j++)
            if(strcmp(o->algorithms.v[i], mv.v[j].algo) == 0)
            {
                cm_sv_push(&present, o->algorithms.v[i]);
                break;
            }
    printf("\n");
    cm_print_mode_entries(&present, &entry_counts, entries);
    printf("Summary:\n  Manifests: %lu\n  Entries  : %d\n  Updated  : %d\n  Unchanged: %d\n  Backups  : %d\n  Errors   : %d\n\nOperation complete.\n", (unsigned long)mv.n, entries, updated, unchanged, backups, errors);
    cm_timestamp_issues_summary(&timestamp_issues);
    cm_sv_free(&present);
    cm_count_free(&entry_counts);
    cm_dtv_free(&dirs);
    cm_timestamp_issues_free(&timestamp_issues);
    cm_mv_free(&mv);

    return errors ? 1 : 0;
}

/* --------------------------------- join ----------------------------------- */

static int cm_mode_join(const CmOptions *o)
{
    CmManifestVec mv = {0};
    CmCountMap entry_counts = {0};
    CmStrVec present = {0};
    char *base;
    size_t i, j, k;
    int errors = 0, entries = 0, outputs = 0, manifests = 0;

    cm_collect_manifests(o->path, o->recursive, &o->algorithms, o->natural_sort, &mv);
    errors += g_scan_errors;
    if(!mv.n)
    {
        fprintf(stderr, "Error: no selected checksum manifest files found in: %s\n", cm_terminal_path_view(o->path));
        cm_mv_free(&mv);
        return 1;
    }

    base = cm_report_base(o->path);

    /* Validate the output contract before collecting or rewriting records. */
    if(o->algorithms.n > 1)
    {
        const char *dir = o->output ? o->output : base;

        if(o->output && !cm_is_dir(dir))
        {
            fprintf(stderr, "Error: --output must name an existing directory when multiple algorithms/all are selected.\n");
            free(base);
            cm_mv_free(&mv);
            return 2;
        }
        if(!o->output)
            for(i = 0; i < o->algorithms.n; i++)
            {
                char *def = cm_default_output_name(o->algorithms.v[i]);
                char *candidate = cm_path_join(dir, def);

                free(def);
                if(cm_is_dir(candidate))
                {
                    fprintf(stderr, "Error: %s: output path is a directory.\n", cm_terminal_path_view(candidate));
                    free(candidate);
                    free(base);
                    cm_mv_free(&mv);
                    return 2;
                }
                free(candidate);
            }
    }
    else if(o->output && !cm_is_dir(o->output))
    {
        char *parent;

        if(!cm_output_has_extension(o->output, o->algorithms.v[0]))
        {
            fprintf(stderr, "Error: output file for %s must use a recognized manifest extension.\n", o->algorithms.v[0]);
            free(base);
            cm_mv_free(&mv);
            return 2;
        }
        parent = cm_path_dirname(o->output);
        if(!cm_is_dir(parent))
        {
            fprintf(stderr, "Error: output parent directory does not exist: %s\n", cm_terminal_path_view(parent));
            free(parent);
            free(base);
            cm_mv_free(&mv);
            return 2;
        }
        free(parent);
    }
    else if(!o->output)
    {
        char *def = cm_default_output_name(o->algorithms.v[0]);
        char *candidate = cm_path_join(base, def);

        free(def);
        if(cm_is_dir(candidate))
        {
            fprintf(stderr, "Error: %s: output path is a directory.\n", cm_terminal_path_view(candidate));
            free(candidate);
            free(base);
            cm_mv_free(&mv);
            return 2;
        }
        free(candidate);
    }

    for(i = 0; i < o->algorithms.n; i++)
    {
        const char *algo;

        if(g_interrupted)
            break;
        algo = o->algorithms.v[i];

        CmRecordVec out = {0};
        int had_error = 0;
        char *desired = NULL;
        char *def = cm_default_output_name(algo);

        if(o->algorithms.n > 1)
        {
            const char *dir = o->output ? o->output : base;

            if(o->output && !cm_is_dir(dir))
            {
                fprintf(stderr, "Error: --output must name an existing directory when multiple algorithms/all are selected.\n");
                errors++;
                free(def);
                continue;
            }
            desired = cm_path_join(dir, def);
        }
        else if(!o->output)
        {
            desired = cm_path_join(base, def);
        }
        else if(cm_is_dir(o->output))
        {
            desired = cm_path_join(o->output, def);
        }
        else
        {
            if(!cm_output_has_extension(o->output, algo))
            {
                fprintf(stderr, "Error: output file for %s must use a recognized manifest extension.\n", algo);
                errors++;
                free(def);
                continue;
            }
            desired = cm_path_normalize(o->output);
        }
        free(def);

        for(j = 0; j < mv.n; j++)
        {
            CmRecordVec rec = {0};

            if(g_interrupted)
            {
                had_error = 1;
                break;
            }

            int valid_count = 0, has_nul = 0;

            if(strcmp(mv.v[j].algo, algo) != 0)
                continue;
            manifests++;
            if(!cm_read_records(mv.v[j].path, algo, &rec, &valid_count, &has_nul))
            {
                fprintf(stderr, "Error: %s: cannot open manifest.\n", cm_terminal_path_view(mv.v[j].path));
                errors++;
                had_error = 1;
                cm_rv_free(&rec);
                continue;
            }
            if(!valid_count)
            {
                fprintf(stderr, "Error: %s: no valid checksum entries\n", cm_terminal_path_view(mv.v[j].path));
                errors++;
                had_error = 1;
                cm_rv_free(&rec);
                continue;
            }
            for(k = 0; k < rec.n; k++)
            {
                char *target = cm_entry_target(mv.v[j].path, rec.v[k].name, o->path_separator, 1, 0);
                char *rel = cm_relative_path(base, target);
                char *name = cm_path_for_manifest_output(rel, o->path_separator, rec.v[k].name);

                if(!name)
                {
                    fprintf(stderr, "Error: %s: cannot represent entry path.\n", cm_terminal_path_view(mv.v[j].path));
                    errors++;
                    had_error = 1;
                    free(target);
                    free(rel);
                    continue;
                }
                cm_add_record(&out, rec.v[k].digest, name);
                entries++;
                cm_count_inc(&entry_counts, algo);
                free(target);
                free(rel);
                free(name);
            }
            cm_rv_free(&rec);
        }

        if(g_interrupted)
            had_error = 1;
        if(!had_error && out.n)
        {
            char *reserved;

            if(cm_is_dir(desired))
            {
                fprintf(stderr, "Error: %s: output path is a directory.\n", cm_terminal_path_view(desired));
                errors++;
                cm_rv_free(&out);
                free(desired);
                continue;
            }
            reserved = cm_reserve_collision(desired, algo, 0, 0, 0);
            if(!reserved)
            {
                errors++;
            }
            else if(cm_write_records(reserved, algo, &out, o))
            {
                char suffix[128];

                snprintf(suffix, sizeof(suffix), " (%s: %lu entries)", algo, (unsigned long)out.n);
                cm_print_output_path(reserved, suffix);
                outputs++;
            }
            else
            {
                cm_unlink(reserved);
                cm_registry_remove(&g_reserved_paths, reserved);
                errors++;
            }
            free(reserved);
        }
        cm_rv_free(&out);
        free(desired);
    }

    if(g_interrupted)
    {
        cm_sv_free(&present);
        cm_count_free(&entry_counts);
        free(base);
        cm_mv_free(&mv);
        return 1;
    }

    for(i = 0; i < o->algorithms.n; i++)
        for(j = 0; j < mv.n; j++)
            if(strcmp(o->algorithms.v[i], mv.v[j].algo) == 0)
            {
                cm_sv_push(&present, o->algorithms.v[i]);
                break;
            }
    printf("\n");
    cm_print_mode_entries(&present, &entry_counts, entries);
    printf("Summary:\n  Manifests: %d\n  Entries  : %d\n  Outputs  : %d\n  Errors   : %d\n\nOperation complete.\n", manifests, entries, outputs, errors);
    cm_sv_free(&present);
    cm_count_free(&entry_counts);
    free(base);
    cm_mv_free(&mv);

    return errors ? 1 : 0;
}

/* -------------------------------- split ----------------------------------- */

typedef struct
{
    char *path;
    CmRecordVec records;
} CmGroup;

typedef struct
{
    CmGroup *v;
    size_t n, cap;
} CmGroupVec;

static CmGroup *cm_group_get(CmGroupVec *g, const char *path)
{
    size_t i;

    for(i = 0; i < g->n; i++)
        if(strcmp(g->v[i].path, path) == 0)
            return &g->v[i];
    if(g->n == g->cap)
    {
        size_t new_cap = g->cap ? cm_size_mul(g->cap, 2) : 16;

        g->v = (CmGroup *)cm_xrealloc_array(g->v, new_cap, sizeof(CmGroup));
        g->cap = new_cap;
    }

    g->v[g->n].path = cm_xstrdup(path);
    memset(&g->v[g->n].records, 0, sizeof(CmRecordVec));

    return &g->v[g->n++];
}

static void cm_group_free(CmGroupVec *g)
{
    size_t i;

    for(i = 0; i < g->n; i++)
    {
        free(g->v[i].path);
        cm_rv_free(&g->v[i].records);
    }

    free(g->v);
    memset(g, 0, sizeof(*g));
}

static char *cm_split_target(const char *base, const char *outroot, const char *entry, const char *mode, char **basename_out)
{
    char *native = cm_manifest_path_to_native(entry, mode, 0);
    char *root = cm_path_normalize(outroot ? outroot : base);
    char *relative, *target, *bn;

    if(!outroot && cm_path_is_abs(native))
    {
        free(native);
        free(root);
        return NULL;
    }

    if(outroot && cm_path_is_abs(native))
    {
        const char *p = native;
#ifdef _WIN32
        if(isalpha((unsigned char)p[0]) && p[1] == ':')
            p += 2;
#endif
        while(cm_is_sep(*p))
            p++;
        relative = cm_xstrdup(p);
    }
    else
    {
        relative = cm_xstrdup(native);
    }
    {
        char *joined = cm_path_join(root, relative);

        target = cm_path_normalize(joined);
        free(joined);
    }

    if(!cm_same_path_prefix(root, target))
    {
        free(native);
        free(root);
        free(relative);
        free(target);
        return NULL;
    }

    bn = cm_path_basename(target);
    if(!*bn || strcmp(bn, ".") == 0 || strcmp(bn, "..") == 0)
    {
        free(native);
        free(root);
        free(relative);
        free(target);
        free(bn);
        return NULL;
    }

    *basename_out = bn;
    free(native);
    free(root);
    free(relative);

    return target;
}

static int cm_mode_split(const CmOptions *o)
{
    const char *algo = o->algorithms.v[0];
    CmRecordVec rec = {0};
    CmGroupVec groups = {0};
    int vc = 0, hn = 0, errors = 0, entries = 0, outputs = 0;
    size_t i;
    char *base = cm_path_dirname(o->path);
    char *root = o->output ? cm_path_normalize(o->output) : cm_path_normalize(base);

    if(!cm_read_records(o->path, algo, &rec, &vc, &hn))
    {
        if(!g_interrupted)
            fprintf(stderr, "Error: cannot open checksum file: %s\n", cm_terminal_path_view(o->path));
        free(base);
        free(root);
        return 1;
    }

    if(o->output)
    {
        if(cm_exists(root) && !cm_is_dir(root))
        {
            fprintf(stderr, "Error: split --output must name a directory.\n");
            cm_rv_free(&rec);
            free(base);
            free(root);
            return 2;
        }
        if(!cm_is_dir(root) && cm_make_dirs(root) != 0)
        {
            fprintf(stderr, "Error: cannot create split output directory.\n");
            cm_rv_free(&rec);
            free(base);
            free(root);
            return 2;
        }
    }

    if(!vc)
    {
        fprintf(stderr, "Error: %s: no valid checksum entries\n", cm_terminal_path_view(o->path));
        errors++;
    }

    for(i = 0; i < rec.n; i++)
    {
        char *bn = NULL, *target;

        if(g_interrupted)
            break;
        target = cm_split_target(base, o->output ? root : NULL, rec.v[i].name, o->path_separator, &bn);
        if(!target)
        {
            {
                const char *manifest_display = cm_terminal_path_view(o->path);
                const char *entry_display = cm_terminal_path_view(rec.v[i].name);

                fprintf(stderr, "Error: %s:%zu: invalid entry path: %s\n", manifest_display, rec.v[i].line_no, entry_display);
            }
            errors++;
            continue;
        }
        {
            CmBuf b;
            char *intended;
            CmGroup *g;

            cm_buf_init(&b);
            cm_buf_append(&b, target);
            cm_buf_putc(&b, '.');
            cm_buf_append(&b, cm_algo_ext(algo));
            intended = cm_buf_take(&b);
            g = cm_group_get(&groups, intended);
            cm_add_record(&g->records, rec.v[i].digest, bn);
            entries++;
            free(intended);
        }
        free(target);
        free(bn);
    }

    for(i = 0; i < groups.n; i++)
    {
        char *reserved;

        if(g_interrupted)
            break;
        if(!cm_secure_prepare_parent(root, groups.v[i].path))
        {
            fprintf(stderr, "Error: %s: output path escapes through a symlink or invalid parent\n", cm_terminal_path_view(groups.v[i].path));
            errors++;
            continue;
        }
        reserved = cm_reserve_collision(groups.v[i].path, algo, 1, 0, 0);
        if(!reserved)
        {
            errors++;
            continue;
        }
        if(cm_write_records(reserved, algo, &groups.v[i].records, o))
        {
            cm_print_output_path(reserved, NULL);
            outputs++;
        }
        else
        {
            cm_unlink(reserved);
            cm_registry_remove(&g_reserved_paths, reserved);
            if(!g_interrupted)
                errors++;
        }
        free(reserved);
    }

    if(g_interrupted)
    {
        cm_group_free(&groups);
        cm_rv_free(&rec);
        free(base);
        free(root);
        return 1;
    }

    printf("\nSummary:\n  Entries: %d\n  Outputs: %d\n  Errors : %d\n\nOperation complete.\n", entries, outputs, errors);
    cm_group_free(&groups);
    cm_rv_free(&rec);
    free(base);
    free(root);

    return errors ? 1 : 0;
}

/* -------------------------------- remove ---------------------------------- */

static int cm_mode_remove(const CmOptions *o)
{
    CmManifestVec mv = {0};
    CmDirTimeVec dirs = {0};
    CmTimestampIssues timestamp_issues = {0};
    size_t i;
    int errors = 0, removed = 0;
    char *p = cm_path_normalize(o->path);

    {
        char *extensions = cm_extensions_description(&o->algorithms);

        printf("Remove plan:\n  Path               : %s\n  Algorithms         : ", cm_terminal_path_view(p));
        free(p);
        for(i = 0; i < o->algorithms.n; i++)
            printf("%s%s", i ? "," : "", o->algorithms.v[i]);
        printf("\n  Extensions         : %s\n  Recursive          : %s\n  Directory mtime    : %s\n\n", extensions, o->recursive ? "yes" : "no", o->update_timestamp ? "no (-T)" : "yes (best effort)");
        free(extensions);
    }

    if(!cm_prompt_yes("Proceed with removal? [y/N]: ", 0))
    {
        if(g_interrupted)
            return 1;
        printf("Cancelled.\n");
        return 0;
    }

    if(!cm_prompt_yes("Confirm deletion? [y/N]: ", 0))
    {
        if(g_interrupted)
            return 1;
        printf("Cancelled.\n");
        return 0;
    }

    if(!cm_prompt_yes("Type exactly \"yes\" to delete: ", 1))
    {
        if(g_interrupted)
            return 1;
        printf("\nCancelled.\n");
        return 0;
    }

    printf("\n");
    cm_collect_manifests(o->path, o->recursive, &o->algorithms, 0, &mv);
    errors += g_scan_errors;
    if(!mv.n)
    {
        fprintf(stderr, "Error: no selected checksum manifest files found in: %s\n", cm_terminal_path_view(o->path));
        cm_mv_free(&mv);
        return 1;
    }

    if(!o->update_timestamp)
        for(i = 0; i < mv.n; i++)
        {
            char *d = cm_path_dirname(mv.v[i].path);

            cm_dtv_capture(&dirs, &timestamp_issues, d);
            free(d);
        }
    for(i = 0; i < mv.n; i++)
    {
        if(g_interrupted)
            break;
        if(cm_unlink(mv.v[i].path) != 0)
        {
            fprintf(stderr, "Error: %s: cannot remove checksum manifest.\n", cm_terminal_path_view(mv.v[i].path));
            errors++;
        }
        else
        {
            {
                char *safe = cm_sanitize_report_text(cm_terminal_path_view(mv.v[i].path));

                printf("[REMOVED]: %s\n", safe);
                free(safe);
            }
            removed++;
        }
    }

    if(!o->update_timestamp)
        cm_dtv_restore(&dirs, &timestamp_issues);
    if(g_interrupted)
    {
        cm_timestamp_issues_summary(&timestamp_issues);
        cm_dtv_free(&dirs);
        cm_timestamp_issues_free(&timestamp_issues);
        cm_mv_free(&mv);
        return 1;
    }

    printf("\nSummary:\n  Selected: %lu\n  Removed : %d\n  Errors  : %d\n\nOperation complete.\n", (unsigned long)mv.n, removed, errors);
    cm_timestamp_issues_summary(&timestamp_issues);
    cm_dtv_free(&dirs);
    cm_timestamp_issues_free(&timestamp_issues);
    cm_mv_free(&mv);

    return errors ? 1 : 0;
}

/* ---------------------------- argument parsing ---------------------------- */

static void cm_options_init(CmOptions *o)
{
    memset(o, 0, sizeof(*o));
    o->newline_mode = cm_xstrdup("unix");
    o->path_separator = cm_xstrdup("slash");
    o->filter_pattern = cm_xstrdup("*");
    o->filter_case = cm_xstrdup("sensitive");
    o->layout = cm_xstrdup("separate");
}

static void cm_options_free(CmOptions *o)
{
    free(o->mode);
    cm_sv_free(&o->algorithms);
    cm_sv_free(&o->source_algorithms);
    cm_sv_free(&o->check_paths);
    free(o->path);
    free(o->output);
    free(o->delimiter);
    free(o->newline_mode);
    free(o->path_separator);
    free(o->filter_pattern);
    free(o->filter_case);
    free(o->layout);
    free(o->tools_raw);
    cm_pov_free(&o->tools);
    memset(o, 0, sizeof(*o));
}

static int cm_usage_error(const char *program, const char *msg)
{
    char *display = cm_program_display_name(program);

    fprintf(stderr, "Error: %s\nTry %s --help for usage.\n", msg, display);
    free(display);

    return 2;
}

static char *cm_opt_value_eq(const char *arg, const char *name)
{
    size_t n = strlen(name);

    if(strncmp(arg, name, n) == 0 && arg[n] == '=')
        return cm_xstrdup(arg + n + 1);
    return NULL;
}

static int cm_mode_name(const char *raw, char **out)
{
    char *m = cm_xstrdup(raw);

    cm_ascii_lower_inplace(m);
    if(strcmp(m, "check") == 0 || strcmp(m, "c") == 0)
    {
        free(m);
        *out = cm_xstrdup("check");
        return 1;
    }

    if(strcmp(m, "hash") == 0 || strcmp(m, "h") == 0)
    {
        free(m);
        *out = cm_xstrdup("hash");
        return 1;
    }

    if(strcmp(m, "generate") == 0 || strcmp(m, "g") == 0)
    {
        free(m);
        *out = cm_xstrdup("generate");
        return 1;
    }

    if(strcmp(m, "derive") == 0 || strcmp(m, "d") == 0)
    {
        free(m);
        *out = cm_xstrdup("derive");
        return 1;
    }

    if(strcmp(m, "format") == 0 || strcmp(m, "f") == 0)
    {
        free(m);
        *out = cm_xstrdup("format");
        return 1;
    }

    if(strcmp(m, "join") == 0 || strcmp(m, "j") == 0)
    {
        free(m);
        *out = cm_xstrdup("join");
        return 1;
    }

    if(strcmp(m, "split") == 0 || strcmp(m, "s") == 0)
    {
        free(m);
        *out = cm_xstrdup("split");
        return 1;
    }

    if(strcmp(m, "remove") == 0 || strcmp(m, "r") == 0)
    {
        free(m);
        *out = cm_xstrdup("remove");
        return 1;
    }

    free(m);

    return 0;
}

static void cm_replace_string(char **dst, const char *src)
{
    free(*dst);
    *dst = cm_xstrdup(src);
}

static int cm_parse_args(int argc, char **argv, CmOptions *o, int *immediate)
{
    const char *program = argc > 0 ? argv[0] : "checksum-manifest";
    int i;
    CmStrVec positional = {0};
    char *source_raw = NULL, *filter_case_raw = NULL;

    *immediate = -1;
    if(argc < 2)
    {
        *immediate = cm_usage_error(program, "a mode is required: check, hash, generate, derive, format, join, split, or remove");
        return 0;
    }

    if(strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)
    {
        cm_print_help(program);
        *immediate = 0;
        return 0;
    }

    if(strcmp(argv[1], "-v") == 0 || strcmp(argv[1], "--version") == 0)
    {
        cm_print_version(program);
        *immediate = 0;
        return 0;
    }

    if(!cm_mode_name(argv[1], &o->mode))
    {
        *immediate = cm_usage_error(program, "first argument must be a mode: check, hash, generate, derive, format, join, split, or remove");
        return 0;
    }

    if(argc < 3)
    {
        *immediate = cm_usage_error(program, "ALGORITHMS is required after the mode");
        return 0;
    }

    if(strcmp(argv[2], "-h") == 0 || strcmp(argv[2], "--help") == 0)
    {
        cm_print_help(program);
        *immediate = 0;
        return 0;
    }

    if(strcmp(argv[2], "-v") == 0 || strcmp(argv[2], "--version") == 0)
    {
        cm_print_version(program);
        *immediate = 0;
        return 0;
    }

    {
        int transform = strcmp(o->mode, "format") == 0 || strcmp(o->mode, "join") == 0 || strcmp(o->mode, "remove") == 0 || strcmp(o->mode, "split") == 0;

        if(!cm_parse_selector(argv[2], transform, 0, &o->algorithms))
        {
            char msg[512];

            snprintf(msg, sizeof(msg), "invalid ALGORITHMS selector for %s: %s", o->mode, argv[2]);
            *immediate = cm_usage_error(program, msg);
            return 0;
        }
        if(strcmp(o->mode, "split") == 0 && o->algorithms.n != 1)
        {
            *immediate = cm_usage_error(program, "split requires exactly one algorithm");
            return 0;
        }
    }

    for(i = 3; i < argc; i++)
    {
        const char *a = argv[i];
        char *eq = NULL;

        if(strcmp(a, "--") == 0)
        {
            for(i++; i < argc; i++)
                cm_sv_push(&positional, argv[i]);
            break;
        }
        if(strcmp(a, "-r") == 0 || strcmp(a, "--recursive") == 0)
        {
            o->recursive = 1;
        }
        else if(strcmp(a, "-N") == 0 || strcmp(a, "--natural-sort") == 0)
        {
            o->natural_sort = 1;
        }
        else if(strcmp(a, "-L") == 0 || strcmp(a, "--lexicographic-sort") == 0)
        {
            o->lexicographic_sort = 1;
        }
        else if(strcmp(a, "-T") == 0 || strcmp(a, "--update-timestamp") == 0)
        {
            o->update_timestamp = 1;
        }
        else if(strcmp(a, "-b") == 0 || strcmp(a, "--backup") == 0)
        {
            o->backup = 1;
        }
        else if(strcmp(a, "-D") == 0 || strcmp(a, "--digest-only") == 0)
        {
            o->digest_only = 1;
        }
        else if(strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0)
        {
            cm_print_help(program);
            *immediate = 0;
            cm_sv_free(&positional);
            free(source_raw);
            free(filter_case_raw);
            return 0;
        }
        else if(strcmp(a, "-v") == 0 || strcmp(a, "--version") == 0)
        {
            cm_print_version(program);
            *immediate = 0;
            cm_sv_free(&positional);
            free(source_raw);
            free(filter_case_raw);
            return 0;
        }
        else if(strcmp(a, "-o") == 0 || strcmp(a, "--output") == 0 || strcmp(a, "-d") == 0 || strcmp(a, "--delimiter") == 0 ||
            strcmp(a, "-n") == 0 || strcmp(a, "--newline") == 0 || strcmp(a, "-s") == 0 || strcmp(a, "--path-separator") == 0 ||
            strcmp(a, "-t") == 0 || strcmp(a, "--tools") == 0 || strcmp(a, "-F") == 0 || strcmp(a, "--from") == 0 ||
            strcmp(a, "-f") == 0 || strcmp(a, "--filter") == 0 || strcmp(a, "-C") == 0 || strcmp(a, "--filter-case") == 0 ||
            strcmp(a, "-l") == 0 || strcmp(a, "--layout") == 0)
        {
            const char *v;

            if(i + 1 >= argc)
            {
                char msg[256];

                snprintf(msg, sizeof(msg), "option requires a value: %s", a);
                *immediate = cm_usage_error(program, msg);
                cm_sv_free(&positional);
                free(source_raw);
                free(filter_case_raw);
                return 0;
            }
            v = argv[++i];
            if(strcmp(a, "-o") == 0 || strcmp(a, "--output") == 0)
            {
                cm_replace_string(&o->output, v);
            }
            else if(strcmp(a, "-d") == 0 || strcmp(a, "--delimiter") == 0)
            {
                cm_replace_string(&o->delimiter, v);
            }
            else if(strcmp(a, "-n") == 0 || strcmp(a, "--newline") == 0)
            {
                cm_replace_string(&o->newline_mode, v);
                o->newline_explicit = 1;
            }
            else if(strcmp(a, "-s") == 0 || strcmp(a, "--path-separator") == 0)
            {
                cm_replace_string(&o->path_separator, v);
                o->path_separator_explicit = 1;
            }
            else if(strcmp(a, "-t") == 0 || strcmp(a, "--tools") == 0)
            {
                cm_replace_string(&o->tools_raw, v);
            }
            else if(strcmp(a, "-F") == 0 || strcmp(a, "--from") == 0)
            {
                free(source_raw);
                source_raw = cm_xstrdup(v);
            }
            else if(strcmp(a, "-f") == 0 || strcmp(a, "--filter") == 0)
            {
                cm_replace_string(&o->filter_pattern, v);
                o->filter_explicit = 1;
            }
            else if(strcmp(a, "-C") == 0 || strcmp(a, "--filter-case") == 0)
            {
                free(filter_case_raw);
                filter_case_raw = cm_xstrdup(v);
                o->filter_case_explicit = 1;
            }
            else
            {
                cm_replace_string(&o->layout, v);
                o->layout_explicit = 1;
            }
        }
        else if((eq = cm_opt_value_eq(a, "--output")) != NULL)
        {
            cm_replace_string(&o->output, eq);
            free(eq);
        }
        else if((eq = cm_opt_value_eq(a, "--delimiter")) != NULL)
        {
            cm_replace_string(&o->delimiter, eq);
            free(eq);
        }
        else if((eq = cm_opt_value_eq(a, "--newline")) != NULL)
        {
            cm_replace_string(&o->newline_mode, eq);
            o->newline_explicit = 1;
            free(eq);
        }
        else if((eq = cm_opt_value_eq(a, "--path-separator")) != NULL)
        {
            cm_replace_string(&o->path_separator, eq);
            o->path_separator_explicit = 1;
            free(eq);
        }
        else if((eq = cm_opt_value_eq(a, "--tools")) != NULL)
        {
            cm_replace_string(&o->tools_raw, eq);
            free(eq);
        }
        else if((eq = cm_opt_value_eq(a, "--from")) != NULL)
        {
            free(source_raw);
            source_raw = eq;
        }
        else if((eq = cm_opt_value_eq(a, "--filter")) != NULL)
        {
            cm_replace_string(&o->filter_pattern, eq);
            o->filter_explicit = 1;
            free(eq);
        }
        else if((eq = cm_opt_value_eq(a, "--filter-case")) != NULL)
        {
            free(filter_case_raw);
            filter_case_raw = eq;
            o->filter_case_explicit = 1;
        }
        else if((eq = cm_opt_value_eq(a, "--layout")) != NULL)
        {
            cm_replace_string(&o->layout, eq);
            o->layout_explicit = 1;
            free(eq);
        }
        else if(a[0] == '-')
        {
            char msg[256];

            snprintf(msg, sizeof(msg), "unknown option: %s", a);
            *immediate = cm_usage_error(program, msg);
            cm_sv_free(&positional);
            free(source_raw);
            free(filter_case_raw);
            return 0;
        }
        else
        {
            cm_sv_push(&positional, a);
        }
    }

    if(strcmp(o->mode, "check") == 0)
    {
        if(!positional.n)
        {
            *immediate = cm_usage_error(program, "at least one PATH/CHECKSUM_FILE is required");
            goto fail;
        }
        for(i = 0; i < (int)positional.n; i++)
            cm_sv_push(&o->check_paths, positional.v[i]);
        o->path = cm_xstrdup(positional.v[0]);
    }
    else
    {
        if(positional.n != 1)
        {
            *immediate = cm_usage_error(program, "exactly one PATH/CHECKSUM_FILE is required");
            goto fail;
        }
        o->path = cm_xstrdup(positional.v[0]);
    }

    if(strcmp(o->mode, "format") == 0 && o->output)
    {
        *immediate = cm_usage_error(program, "--output is not valid with format");
        goto fail;
    }

    if(strcmp(o->mode, "remove") == 0 && o->output)
    {
        *immediate = cm_usage_error(program, "--output is not valid with remove");
        goto fail;
    }

    if(o->output && !*o->output)
    {
        *immediate = cm_usage_error(program, "--output must not be empty");
        goto fail;
    }

    if(o->delimiter)
    {
        int noncrc = 0;
        size_t q;

        for(q = 0; q < o->algorithms.n; q++)
            if(!cm_algo_crc(o->algorithms.v[q]))
                noncrc = 1;
        if(noncrc && strcmp(o->delimiter, "  ") != 0 && strcmp(o->delimiter, " *") != 0)
        {
            *immediate = cm_usage_error(program, "--delimiter must be exactly two spaces or \" *\" for non-CRC algorithms");
            goto fail;
        }
    }

    {
        char *n = cm_xstrdup(o->newline_mode);

        cm_ascii_lower_inplace(n);
        if(strcmp(n, "unix") && strcmp(n, "lf") && strcmp(n, "windows") && strcmp(n, "crlf") && strcmp(n, "classic-mac") && strcmp(n, "cr") && strcmp(n, "system"))
        {
            char msg[512];

            snprintf(msg, sizeof(msg), "invalid --newline mode: %s", n);
            free(n);
            *immediate = cm_usage_error(program, msg);
            goto fail;
        }
        cm_replace_string(&o->newline_mode, n);
        free(n);
    }

    {
        char *s = cm_xstrdup(o->path_separator);

        cm_ascii_lower_inplace(s);
        if(strcmp(s, "slash") && strcmp(s, "backslash") && strcmp(s, "default") && strcmp(s, "system"))
        {
            char msg[512];

            snprintf(msg, sizeof(msg), "invalid --path-separator mode: %s", s);
            free(s);
            *immediate = cm_usage_error(program, msg);
            goto fail;
        }
        cm_replace_string(&o->path_separator, s);
        free(s);
    }

    if(o->backup && strcmp(o->mode, "format") != 0)
    {
        *immediate = cm_usage_error(program, "--backup is only valid with format");
        goto fail;
    }

    if(o->digest_only && strcmp(o->mode, "hash") != 0)
    {
        *immediate = cm_usage_error(program, "--digest-only is only valid with hash");
        goto fail;
    }

    if(o->update_timestamp && strcmp(o->mode, "format") && strcmp(o->mode, "derive") && strcmp(o->mode, "remove"))
    {
        *immediate = cm_usage_error(program, "--update-timestamp is only valid with format/derive/remove");
        goto fail;
    }

    if(strcmp(o->mode, "remove") == 0 && (o->delimiter || o->newline_explicit || o->path_separator_explicit))
    {
        *immediate = cm_usage_error(program, "--delimiter, --newline, and --path-separator are not valid with remove");
        goto fail;
    }

    if(strcmp(o->mode, "generate") == 0 || strcmp(o->mode, "hash") == 0)
    {
        if(o->filter_case_explicit && !o->filter_explicit)
        {
            *immediate = cm_usage_error(program, "--filter-case requires --filter");
            goto fail;
        }
        if(filter_case_raw)
        {
            char *c = cm_xstrdup(filter_case_raw);

            cm_ascii_lower_inplace(c);
            if(strcmp(c, "sensitive") && strcmp(c, "insensitive"))
            {
                char msg[512];

                snprintf(msg, sizeof(msg), "invalid --filter-case mode: %s", c);
                free(c);
                *immediate = cm_usage_error(program, msg);
                goto fail;
            }
            cm_replace_string(&o->filter_case, c);
            free(c);
        }
        if(o->natural_sort && o->lexicographic_sort)
        {
            *immediate = cm_usage_error(program, "--natural-sort and --lexicographic-sort are mutually exclusive");
            goto fail;
        }
        if(strcmp(o->mode, "generate") == 0)
        {
            char *l = cm_xstrdup(o->layout);

            cm_ascii_lower_inplace(l);
            if(strcmp(l, "separate") && strcmp(l, "single"))
            {
                char msg[512];

                snprintf(msg, sizeof(msg), "invalid --layout mode: %s", l);
                free(l);
                *immediate = cm_usage_error(program, msg);
                goto fail;
            }
            cm_replace_string(&o->layout, l);
            free(l);
            if(o->natural_sort && strcmp(o->layout, "single") != 0)
            {
                *immediate = cm_usage_error(program, "--natural-sort requires --layout single with generate");
                goto fail;
            }
            if(o->lexicographic_sort && strcmp(o->layout, "single") != 0)
            {
                *immediate = cm_usage_error(program, "--lexicographic-sort requires --layout single with generate");
                goto fail;
            }
        }
        else if(o->layout_explicit)
        {
            *immediate = cm_usage_error(program, "--layout is only valid with generate");
            goto fail;
        }
    }
    else if(strcmp(o->mode, "join") == 0 || strcmp(o->mode, "derive") == 0)
    {
        if(o->natural_sort && o->lexicographic_sort)
        {
            *immediate = cm_usage_error(program, "--natural-sort and --lexicographic-sort are mutually exclusive");
            goto fail;
        }
        if(o->filter_explicit || o->filter_case_explicit || o->layout_explicit)
        {
            *immediate = cm_usage_error(program, "--filter and --filter-case are only valid with generate/hash; --layout is only valid with generate");
            goto fail;
        }
    }
    else
    {
        if(o->filter_explicit || o->filter_case_explicit || o->layout_explicit)
        {
            *immediate = cm_usage_error(program, "--filter and --filter-case are only valid with generate/hash; --layout is only valid with generate");
            goto fail;
        }
        if(o->natural_sort || o->lexicographic_sort)
        {
            *immediate = cm_usage_error(program, "--natural-sort and --lexicographic-sort are only valid with hash/generate/join/derive");
            goto fail;
        }
    }

    if(strcmp(o->mode, "split") == 0 && o->recursive)
    {
        *immediate = cm_usage_error(program, "--recursive is not valid with split");
        goto fail;
    }

    if(strcmp(o->mode, "check") && strcmp(o->mode, "hash") && strcmp(o->mode, "generate") && strcmp(o->mode, "derive") && o->tools_raw)
    {
        *immediate = cm_usage_error(program, "--tools is only valid with check/hash/generate/derive");
        goto fail;
    }

    if(strcmp(o->mode, "derive") == 0)
    {
        if(!source_raw)
        {
            *immediate = cm_usage_error(program, "--from SOURCE_ALGORITHMS is required with derive");
            goto fail;
        }
        if(!cm_parse_selector(source_raw, 1, 0, &o->source_algorithms))
        {
            char msg[512];

            snprintf(msg, sizeof(msg), "invalid --from algorithm selector: %s", source_raw);
            *immediate = cm_usage_error(program, msg);
            goto fail;
        }
    }
    else if(source_raw)
    {
        *immediate = cm_usage_error(program, "--from is only valid with derive");
        goto fail;
    }

    if(o->tools_raw && !cm_parse_tools(o->tools_raw, &o->algorithms, &o->tools))
    {
        char msg[768];

        snprintf(msg, sizeof(msg), "invalid --tools specification: %s", o->tools_raw);
        *immediate = cm_usage_error(program, msg);
        goto fail;
    }

    cm_sv_free(&positional);
    free(source_raw);
    free(filter_case_raw);

    return 1;
fail:
    cm_sv_free(&positional);
    free(source_raw);
    free(filter_case_raw);

    return 0;
}

int main(int argc, char **argv)
{
    CmOptions o;
    int immediate, rc = 0;

    cm_options_init(&o);
    signal(SIGINT, cm_signal_handler);
    signal(SIGTERM, cm_signal_handler);
    srand((unsigned)time(NULL));
    if(!cm_parse_args(argc, argv, &o, &immediate))
    {
        rc = immediate >= 0 ? immediate : 2;
        cm_options_free(&o);
        cm_cleanup_artifacts();
        return rc;
    }

    if(strcmp(o.mode, "split") == 0 && !cm_is_file(o.path))
    {
        fprintf(stderr, "Error: checksum file does not exist or is not a regular file: %s\n", cm_terminal_path_view(o.path));
        rc = 2;
    }
    else if(strcmp(o.mode, "split") == 0)
    {
        rc = cm_mode_split(&o);
    }
    else if(strcmp(o.mode, "check") == 0 && o.check_paths.n > 1)
    {
        size_t i;

        for(i = 0; i < o.check_paths.n; i++)
            if(!cm_is_file(o.check_paths.v[i]))
            {
                fprintf(stderr, "Error: multiple check inputs must all be regular checksum files: %s\n", cm_terminal_path_view(o.check_paths.v[i]));
                rc = 2;
                break;
            }
        if(!rc)
            rc = cm_mode_check(&o);
    }
    else if(!cm_is_file(o.path) && !cm_is_dir(o.path))
    {
        fprintf(stderr, "Error: path does not exist or is not a regular file/directory: %s\n", cm_terminal_path_view(o.path));
        rc = 2;
    }
    else if(strcmp(o.mode, "hash") == 0)
    {
        rc = cm_mode_hash(&o);
    }
    else if(strcmp(o.mode, "generate") == 0)
    {
        rc = cm_mode_generate(&o);
    }
    else if(strcmp(o.mode, "derive") == 0)
    {
        rc = cm_mode_derive(&o);
    }
    else if(strcmp(o.mode, "format") == 0)
    {
        rc = cm_mode_format(&o);
    }
    else if(strcmp(o.mode, "join") == 0)
    {
        rc = cm_mode_join(&o);
    }
    else if(strcmp(o.mode, "remove") == 0)
    {
        rc = cm_mode_remove(&o);
    }
    else if(strcmp(o.mode, "check") == 0)
    {
        rc = cm_mode_check(&o);
    }
    else
    {
        rc = 2;
    }
    if(g_interrupted)
    {
        cm_cleanup_artifacts();
        rc = 128 + (int)g_interrupted;
    }
    else
    {
        cm_cleanup_artifacts();
    }
    cm_options_free(&o);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    if(g_ossl_legacy)
        OSSL_PROVIDER_unload(g_ossl_legacy);
    if(g_ossl_default)
        OSSL_PROVIDER_unload(g_ossl_default);
#endif
    return rc;
}
