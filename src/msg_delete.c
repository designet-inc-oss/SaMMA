/*
 * samma
 * msg_delete.c
 *
 * delete
 */


#include <string.h>
#include <stdlib.h>
#include <libdgstr.h>

#include <gmime/gmime.h>

#include "harmless.h"
#include "msg_delete.h"

int msg_delete(GMimeObject *part, GMimeObject **new, harmless_proc_arg_t *arg)
{
    char *tmp;
    int ret;
    struct strtag tag = { "mimetype", 8, NULL };

    tmp = g_mime_content_type_to_string(g_mime_object_get_content_type((GMimeObject *)part));
    tag.st_str = tmp == NULL ? "Unknown part" : tmp;

    ret = strcat_proc_message(
        &(arg->message),
        &(arg->message_length),
        arg->cfg->cf_harmlessmessagedelete,
        &tag,
        1
    );

    free(tmp);
    return ret;
}
