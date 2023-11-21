/*
 * samma
 * msg_delete.h
 *
 */
#ifndef _MSG_DELETE_H
#define _MSG_DELETE_H

#include "harmless.h"

/**
 * error messages
 */


/**
 * type def
 */
#define MSG_DEL_OK		1;
#define MSG_DEL_NG		0;



/**
 * functions
 */

int msg_delete(GMimeObject *, GMimeObject **, harmless_proc_arg_t *);


#endif		/* _MSG_DELETE_H */
