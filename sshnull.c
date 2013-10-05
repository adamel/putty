/*
 * Null host key algorithm for PuTTY.
 *
 * Specified in RFC 4462, section 5. Used for GSS key exchange; should
 * not be made known to the key management tools.
 */
#include "ssh.h"

static void *null_newkey(char *data, int len)
{
    /* We really don't have a key, so return NULL. */
    return NULL;
}

static void null_freekey(void *key)
{
    /* No-op */
}

static char *null_fmtkey(void *key)
{
    /* Return the string "null". */
    char *p;

    p = snewn(sizeof("null"), char);
    if (!p)
	return NULL;
    strcpy(p, "null");
    return p;
}

/*
 * Functions set to NULL should never be called.
 */
const struct ssh_signkey ssh_null = {
    null_newkey,
    null_freekey,
    null_fmtkey,	/* Always "null" */
    NULL,		/* public_blob */
    NULL,		/* private_blob */
    NULL,		/* createkey */
    NULL,		/* openssh_createkey */
    NULL,		/* openssh_fmtkey */
    NULL,		/* pubkey_bits */
    null_fmtkey,	/* fingerprint - Always "null" */
    NULL,		/* verifysig */
    NULL,		/* sign */
    "null",
    NULL,		/* for host key cache */
};
