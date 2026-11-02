/* Regression probe for upstream CVE-2026-18374; executed only in the build container.
   Return-value checks alone cannot demonstrate memory safety: the old code can
   corrupt the heap before returning EINVAL. Pair this probe with Valgrind
   Memcheck via tools/libc_fopen_regression.sh; it reports the loaded libc's
   GNU build ID so runs can be attributed to an exact binary. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <wchar.h>

static char build_id[41] = "unavailable";

static void record_build_id(void) {
    Dl_info info = {0};
    if (!dladdr((void *)fopen, &info) || !info.dli_fname) return;
    int fd = open(info.dli_fname, O_RDONLY);
    if (fd < 0) return;
    Elf64_Ehdr ehdr;
    if (read(fd, &ehdr, sizeof ehdr) != (ssize_t)sizeof ehdr) { close(fd); return; }
    for (int i = 0; i < ehdr.e_phnum; i++) {
        Elf64_Phdr phdr;
        if (pread(fd, &phdr, sizeof phdr, ehdr.e_phoff + (Elf64_Off)i * ehdr.e_phentsize) != (ssize_t)sizeof phdr) break;
        if (phdr.p_type != PT_NOTE) continue;
        unsigned char *notes = malloc(phdr.p_filesz);
        if (!notes) break;
        if (pread(fd, notes, phdr.p_filesz, phdr.p_offset) != (ssize_t)phdr.p_filesz) { free(notes); break; }
        size_t off = 0;
        while (off + sizeof(Elf64_Nhdr) <= phdr.p_filesz) {
            Elf64_Nhdr *nh = (Elf64_Nhdr *)(notes + off);
            size_t name = (nh->n_namesz + 3) & ~(size_t)3;
            size_t desc = (nh->n_descsz + 3) & ~(size_t)3;
            if (off + sizeof(*nh) + name + desc > phdr.p_filesz) break;
            if (nh->n_type == NT_GNU_BUILD_ID && nh->n_namesz == 4
                && memcmp(nh + 1, "GNU", 4) == 0 && nh->n_descsz == 20) {
                unsigned char *id = (unsigned char *)nh + sizeof(*nh) + name;
                for (int j = 0; j < 20; j++) sprintf(build_id + j * 2, "%02x", id[j]);
                free(notes);
                close(fd);
                return;
            }
            off += sizeof(*nh) + name + desc;
        }
        free(notes);
    }
    close(fd);
}

struct read_case {
    const char *name;
    const char *mode;
    const char *bytes;        /* written verbatim; no NUL bytes */
    const wchar_t *expected;  /* wide characters fgetwc must return, then WEOF */
};

static int run_read_case(const struct read_case *c) {
    char path[] = "/tmp/fopen-regression-input-XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) return 0;
    int ok = write(fd, c->bytes, strlen(c->bytes)) == (ssize_t)strlen(c->bytes);
    close(fd);
    if (!ok) { unlink(path); return 0; }
    FILE *file = fopen(path, c->mode);
    unlink(path);
    if (!file) return 0;
    ok = 0;
    for (const wchar_t *p = c->expected;; p++) {
        wint_t ch = fgetwc(file);
        if (ch == WEOF) { ok = *p == L'\0'; break; }
        if (*p == L'\0' || ch != (wint_t)*p) break;
    }
    if (fclose(file) != 0) ok = 0;
    return ok;
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    setvbuf(stdout, NULL, _IONBF, 0);
    record_build_id();
    static const struct read_case reads[] = {
        {"read-utf8", "r,ccs=UTF-8", "h\xc3\xa9llo w\xc3\xb6rld\n", L"h\xe9llo w\xf6rld\n"},
        {"read-ascii", "r,ccs=ASCII", "Stargate 25\n", L"Stargate 25\n"},
        /* ISO-8859-1 is resolved through an external gconv module, unlike the
           internal UTF-8/ASCII converters. */
        {"read-latin1", "r,ccs=ISO-8859-1", "\xe9" "A\n", L"\xe9" L"A\n"},
    };
    for (size_t i = 0; i < sizeof reads / sizeof reads[0]; i++) {
        if (strcmp(argv[1], reads[i].name) == 0) {
            int passed = run_read_case(&reads[i]);
            printf("{\"case\":\"%s\",\"passed\":%s,\"errno\":0,\"fopen_library\":\"%s\",\"libc_build_id\":\"%s\"}\n",
                   argv[1], passed ? "true" : "false", "read-case", build_id);
            return passed ? 0 : 1;
        }
    }
    const char *mode = NULL;
    int valid = 0;
    char *allocated = NULL;
    if (!strcmp(argv[1], "overflow")) {
        size_t size = 8192;
        allocated = malloc(size + 9);
        if (!allocated) return 3;
        memcpy(allocated, "r,ccs=,", 7);
        memset(allocated + 7, 'A', size);
        allocated[size + 7] = '\0';
        mode = allocated;
    } else if (!strcmp(argv[1], "empty")) mode = "r,ccs=";
    else if (!strcmp(argv[1], "empty-comma")) mode = "r,ccs=,UTF-8";
    else if (!strcmp(argv[1], "spaces")) mode = "r,ccs=  ,UTF-8";
    else if (!strcmp(argv[1], "punctuation")) mode = "r,ccs=////,UTF-8";
    else if (!strcmp(argv[1], "invalid")) mode = "r,ccs=NO_SUCH_CHARACTER_SET";
    else if (!strcmp(argv[1], "utf8")) { mode = "r,ccs=UTF-8"; valid = 1; }
    else if (!strcmp(argv[1], "ascii")) { mode = "r,ccs=ASCII"; valid = 1; }
    else if (!strcmp(argv[1], "normal")) { mode = "r"; valid = 1; }
    else return 2;
    errno = 0;
    FILE *file = fopen("/dev/null", mode);
    int error = errno;
    int passed = valid ? file != NULL : file == NULL && error == EINVAL;
    if (file) {
        if (valid && strcmp(argv[1], "normal") && fgetwc(file) != WEOF) passed = 0;
        fclose(file);
    }
    free(allocated);
    Dl_info library = {0};
    dladdr((void *)fopen, &library);
    printf("{\"case\":\"%s\",\"passed\":%s,\"errno\":%d,\"fopen_library\":\"%s\",\"libc_build_id\":\"%s\"}\n",
           argv[1], passed ? "true" : "false", error,
           library.dli_fname ? library.dli_fname : "unknown", build_id);
    return passed ? 0 : 1;
}
