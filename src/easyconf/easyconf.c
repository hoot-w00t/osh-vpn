#include "easyconf.h"
#include "getline.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

ec_t *ec_create(void)
{
    ec_t *ec;

    if (!(ec = malloc(sizeof(ec_t))))
        return NULL;

    memset(ec, 0, sizeof(ec_t));
    return ec;
}

void ec_destroy(ec_t *ec)
{
    ecp_t *ecp;
    ecp_t *next_ecp = NULL;

    if (ec) {
        ecp = ec->head;
        while (ecp) {
            next_ecp = ecp->next;
            ecp_free(ecp);
            ecp = next_ecp;
        }
        free(ec);
    }
}

/*
Append *ecp to *ec
*/
static void ec_append(ec_t *ec, ecp_t *ecp)
{
    if (!(ec && ecp)) return;

    if (ec->head) {
        ec->tail->next = ecp;
        ecp->prev = ec->tail;
        ec->tail = ecp;
    } else {
        ec->head = ecp;
        ec->tail = ecp;
    }
}

ecp_t *ec_find(ec_t *ec, const char *name)
{
    if (name) {
        ec_foreach(ecp, ec) {
            if (!ecp->name) continue;
            if (!strcmp(ecp->name, name)) {
                ec->last_find = ecp;
                return ecp;
            }
        }
        ec->last_find = NULL;
    }
    return ec->last_find;
}

ecp_t *ec_next(ec_t *ec)
{
    if (ec->last_find) {
        for (ecp_t *ecp = ec->last_find->next; ecp; ecp = ecp->next) {
            if (!ecp->name) continue;
            if (!strcmp(ecp->name, ec->last_find->name)) {
                ec->last_find = ecp;
                return ecp;
            }
        }
        ec->last_find = NULL;
    }
    return NULL;
}

int ec_set(ec_t *ec, const char *name, const char *value)
{
    ecp_t *ecp = ec_find(ec, name);

    if (ecp) {
        return ecp_set_value(ecp, value);
    } else {
        if (!(ecp = ecp_create(name, value)))
            return -1;
        ec_append(ec, ecp);
    }
    return 0;
}

int ec_unset(ec_t *ec, const char *name)
{
    ecp_t *ecp = ec_find(ec, name);

    if (!ecp) return -1;

    if (ecp == ec->head) {
        if ((ec->head = ec->head->next)) {
            ec->head->prev = NULL;
        } else {
            ec->tail = NULL;
        }
    } else if (ecp == ec->tail) {
        if ((ec->tail = ec->tail->prev))
            ec->tail->next = NULL;
    } else {
        ecp->prev->next = ecp->next;
        ecp->next->prev = ecp->prev;
    }
    ecp_free(ecp);
    return 0;
}

ec_t *ec_load_from_file(const char *filename)
{
    char *line;
    FILE *file;
    ec_t *ec;
    ecp_t *ecp;

    if (!(file = fopen(filename, "r")))
        return NULL;
    if (!(ec = ec_create())) {
        fclose(file);
        return NULL;
    }

    while ((line = ec_getline(file))) {
        if ((ecp = ecp_parse_line(line)))
            ec_append(ec, ecp);
        free(line);
    }
    fclose(file);
    return ec;
}

int ec_save_to_file(ec_t *ec, const char *filename)
{
    FILE *file;

    if (!(file = fopen(filename, "w")))
        return -1;

    ec_foreach(ecp, ec) {
        if (ecp->name) {
            if (ecp->value) {
                fprintf(file, "%s\t%s\n", ecp->name, ecp->value);
            } else {
                fprintf(file, "%s\n", ecp->name);
            }
        }
    }
    fflush(file);
    fclose(file);
    return 0;
}