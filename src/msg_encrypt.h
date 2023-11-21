/*
 * samma
 * msg_encrypt.h
 *
 */
#ifndef _MSG_ENCRYPT_H
#define _MSG_ENCRYPT_H

#include "harmless.h"

/**
 * error messages
 */


/**
 * type def
 */
#define MSG_ENC_OK		1;
#define MSG_ENC_NG		0;



/**
 * functions
 */

int msg_encrypt(GMimeObject *, GMimeObject **, harmless_proc_arg_t *);


#endif		/* _MSG_ENCRYPT_H */

