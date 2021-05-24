#include "easyconf.h"
#include <stdlib.h>
#include <string.h>

ecp_t *ecp_empty(void)
{
    ecp_t *ecp = malloc(sizeof(ecp_t));

    if (ecp) memset(ecp, 0, sizeof(ecp_t));
    return ecp;
}

ecp_t *ecp_create(const char *name, const char *value)
{
    char *d_name = NULL;
    char *d_value = NULL;
    ecp_t *ecp = NULL;

    if (!name || !(d_name = strdup(name)))
        goto fail;
    if (value && !(d_value = strdup(value)))
        goto fail;
    if (!(ecp = malloc(sizeof(ecp_t))))
        goto fail;

    memset(ecp, 0, sizeof(ecp_t));
    ecp->name = d_name;
    ecp->value = d_value;
    return ecp;

fail:
    free(d_name);
    free(d_value);
    free(ecp);
    return NULL;
}

ecp_t *ecp_dup(const ecp_t *ecp)
{
    return ecp ? ecp_create(ecp->name, ecp->value) : NULL;
}

void ecp_free(ecp_t *ecp)
{
    if (ecp) {
        free(ecp->name);
        free(ecp->value);
        free(ecp);
    }
}

int ecp_set_name(ecp_t *ecp, const char *name)
{
    char *d_name;

    if (!ecp || !name) return -1;
    if (!(d_name = strdup(name))) return -1;
    free(ecp->name);
    ecp->name = d_name;
    return 0;
}

int ecp_set_value(ecp_t *ecp, const char *value)
{
    char *d_value;

    if (!ecp) return -1;
    if (value) {
        if (!(d_value = strdup(value))) return -1;
        free(ecp->value);
        ecp->value = d_value;
    } else {
        free(ecp->value);
        ecp->value = NULL;
    }
    return 0;
}

ecp_t *ecp_parse_line(const char *line)
{
    char *buf = NULL;
    size_t buflen;
    char *tmp;
    ecp_t *ecp;
    char *p_name;
    char *p_value;

    if (!line) goto fail;
    if (!(buf = strdup(line))) goto fail;
    if (!(buflen = strlen(buf))) goto fail;

    // Remove trailing newline if present
    if (buf[buflen - 1] == '\n')
        buf[--buflen] = '\0';

    // Remove comments
    tmp = buf;
    while ((tmp = strchr(tmp, '#'))) {
        // The character starts a comment if it not preceded by a backslash
        if (!((tmp - 1) >= buf && *(tmp - 1) == '\\')) {
            *tmp = '\0';
            break;
        }
        memmove(tmp - 1, tmp, strlen(tmp) + 1);
    }

    // Ignore whitespaces before parameter name
    for (p_name = buf; *p_name == ' ' || *p_name == '\t'; ++p_name);
    if (!(*p_name)) goto fail;

    // Go to the first whitespace separator and change it a \0
    for (p_value = p_name; *p_value && *p_value != ' ' && *p_value != '\t'; ++p_value);

    // Move to the next character and end the parameter value
    // if we haven't reached the end of the line
    if (*p_value) {
        *p_value = '\0';
        ++p_value;
    }

    // Ignore whitespaces before the value
    for (; *p_value == ' ' || *p_value == '\t'; ++p_value);

    // Remove trailing whitespaces
    tmp = p_value + strlen(p_value) - 1;
    while (tmp >= p_value) {
        if (*tmp == ' ' || *tmp == '\t') {
            *tmp = '\0';
        } else {
            break;
        }
        --tmp;
    }

    // If the final value is empty, set it to NULL
    if (!(*p_value))
        p_value = NULL;

    ecp = ecp_create(p_name, p_value);
    free(buf);
    return ecp;

fail:
    free(buf);
    return NULL;
}