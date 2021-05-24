#ifndef _EC_EASYCONF_H
#define _EC_EASYCONF_H

#include <stddef.h>

#define EC_VERSION_MAJOR (1)
#define EC_VERSION_MINOR (0)
#define EC_VERSION_PATCH (0)

typedef struct easyconf ec_t;
typedef struct easyconf_parameter ecp_t;

struct easyconf {
    ecp_t *head;
    ecp_t *tail;
    ecp_t *last_find; /* Last ec_find() result on this ec_t */
};

struct easyconf_parameter {
    char *name;  /* Parameter name */
    char *value; /* Parameter value */
    ecp_t *next; /* Next parameter in the linked list */
    ecp_t *prev; /* Previous parameter in the linked list */
};

/* easyconf.c */
/*
Return a dynamically allocated ec_t
Return NULL on error
*/
ec_t *ec_create(void);

/*
Free memory used by *ec
*/
void ec_destroy(ec_t *ec);

/*
Return a pointer to the parameter named with *name
Return NULL if it doesn't exist

If *name is NULL, return the last ec_find() result for *ec
*/
ecp_t *ec_find(ec_t *ec, const char *name);

/*
Does the same as ec_find() but starts at the next item following the original
ec_find() call.
Tries to find the same name.

Return a pointer to the next parameter named with ecp_name(ec->last_find)
Return NULL if it doesn't exist or if there was no previous call to ec_find()
*/
ecp_t *ec_next(ec_t *ec);

/*
Set parameter named with *name to *value
Return 0 on success
Return -1 on error

*ec is left unchanged on error
*/
int ec_set(ec_t *ec, const char *name, const char *value);

/*
Delete parameter named with *name
Return 0 on success
Return -1 on error
*/
int ec_unset(ec_t *ec, const char *name);

/*
Return a dynamically allocated ec_t with the parameters loaded from *filename
Return NULL on error
*/
ec_t *ec_load_from_file(const char *filename);

/*
Save parameters in *ec to *filename
Return 0 on success
Return -1 on error
*/
int ec_save_to_file(ec_t *ec, const char *filename);



/* parameter.c */
/*
Return a pointer to a dynamically allocated ecp_t initialized to 0
Return NULL on error
*/
ecp_t *ecp_empty(void);

/*
Return a pointer to a dynamically allocated and initialized ecp_t
*name and *value are duplicated
Return NULL on error
*/
ecp_t *ecp_create(const char *name, const char *value);

/*
Return a newly allocated copy of *ecp
Return NULL on error
*/
ecp_t *ecp_dup(const ecp_t *ecp);

/*
Free memory used by *ecp
*/
void ecp_free(ecp_t *ecp);

/*
Set ecp->name to *name
Return 0 on success
Return -1 on error

The name is unchanged on error
*/
int ecp_set_name(ecp_t *ecp, const char *name);

/*
Set ecp->value to *value
Return 0 on success
Return -1 on error

The value is unchanged on error
*/
int ecp_set_value(ecp_t *ecp, const char *value);

/*
Return ecp_t with the values parsed from *line
Return NULL on error
*/
ecp_t *ecp_parse_line(const char *line);

/*
Return a const char * to ecp->name
*/
static inline const char *ecp_name(ecp_t *ecp)
{
    return ecp ? ecp->name : NULL;
}

/*
Return a const char * to ecp->value
*/
static inline const char *ecp_value(ecp_t *ecp)
{
    return ecp ? ecp->value : NULL;
}



/*
Iterate through every item in ec starting from the beginning
*/
#define ec_foreach(item, ec) \
    for (ecp_t * item = (ec)->head; item; item = (item)->next)

/*
Iterate through every item in ec starting from the end

*/
#define ec_foreach_reverse(item, ec) \
    for (ecp_t * item = (ec)->tail; item; item = (item)->prev)

#endif