/*
 * samma
 * harmless.h
 *
 * To do SPF check or Sender-IP check or something
 */
#ifndef _HARMLESS_H
#define _HARMLESS_H

#include <gmime/gmime.h>
#include <libmilter/mfapi.h>
#include <libdgstr.h>
#include "mailzip.h"
#include "zipconv.h"
#include "sender_check.h"

/**
 * error messages
 */
#define HARMLESS_ERR_MEM "Cannot allocate memory: %s"
#define HARMLESS_ERR_INVALID "Invalid item is set: %s"

#define HARMLESS_ZIP_LOG "Attachment file was encrypted.: password=%s, source=%s, message-id=%s, recipients=%s"

/**
 * type def
 */
#define HARMLESS_OK		1
#define HARMLESS_NG		0
#define HARMLESS_ERR		-1
#define NO_MATCH_EXTENSION		-2

#define MSG_TAG_S "<@@"
#define MSG_TAG_E "@@>"

typedef struct _harmless_proc_list {
    int (*function)();
    struct _harmless_proc_list *next;
} harmless_proc_list_t;

typedef struct _harmless_proc_arg {
    char *message;
    int message_length;
    char *zipdir;
    int depth;
    int sendercheck;
    int used_extension;
    struct config *cfg;
    sender_check_arg_t *maildata;

    char *mime_extension; // extensionコマンドで再取得したMIMEタイプ
} harmless_proc_arg_t;


char *set_harmless_proc_list(char *setting, void **pointer);
void free_harmless_proc_list(harmless_proc_list_t *list);

int harmless();
int harmless_proc(GMimeMultipart *part, harmless_proc_arg_t *args);
int harmless_proc_single_part(GMimeObject *src, GMimeObject **dst, harmless_proc_arg_t *arg);

char *estimate_filename(GMimeObject *part);
int strcat_proc_message(
    char **msg
    , int *len
    , char* tmpl
    , struct strtag *strtag
    , int tagcount
);

#endif		/* _HARMLESS_H */
