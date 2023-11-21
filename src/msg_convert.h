/*
 * samma
 * msg_convert.h
 *
 */
#ifndef _MSG_CONVERT_H
#define _MSG_CONVERT_H

#include "harmless.h"

/**
 * error messages
 */
#define CONV_ERR_MEM "Cannot allocate memory(msg_convert)"
#define CONV_ERR_READ "Cannot read a config file: %s"
#define CONV_ERR_OPEN "Cannot open a config file: %s :%s"
#define CONV_ERR_TOOLONGLINE    "%s (line: %d) too long line"
#define CONV_ERR_FEW_ITEM    "%s (line: %d) needs more column"
#define CONV_ERR_WITH_LINE "%s (line: %d) ERR:(%s)"
#define CONV_ERR_WRONG_FUNC "%s (line: %d) wrong command(%s)"
#define CONV_ERR_EXEC_EXT "Failed to execute external command.: command=%s, source=%s, message-id=%s, sender=%s, recipients=%s"
#define CONV_ERR_EXEC_IN "Failed to execute internal command.: command=%s, source=%s, message-id=%s, sender=%s, recipients=%s"
#define CONV_ERR_EXEC_ENV "Cannot set environment value for filename.: command=%s, source=%s, message-id=%s, sender=%s, recipients=%s"

#define MIME_ERR_READ    "Cannot read a config file: %s"
#define MIME_ERR_OPEN    "Cannot open a config file: %s :%s"
#define MIME_ERR_MEM     "Cannot allocate memory(read_mimetypes)"
#define EXTE_ERR_MEM     "Cannot allocate memory(convert_extension)"
#define MIME_TOOLONGLINE "%s (line: %d) too long line"

#define NOT_FOUND_FILENAME  "Cannot find a file name."
#define NOT_FOUND_EXTENSION "Cannot find a extension in filename. (%s)"
#define NO_EXTENSION_INMIME "Cannot find a extension in mimetypes. (%s)"

/**
 * type def
 */
#define MSG_RESTRAIN    1
#define MSG_NO_RESTRAIN 0

#define USED_EXTENSION  1

enum {
    FUNCTION,
    COMMAND,
};


// config構造体にセットするもの
typedef struct command_list {
    char *mime_before;
    char *mime_after;
    char *file_extension;

    char *command_name; /* 関数もしくはコマンド名 */
    int command_type;	/* 指定されたコマンドが外部コマンドかどうか */
    int msg_restraint;  /* メッセージを抑制するかどうか */
    int msg_next;       /* 外部コマンド失敗のログを抑制するかどうか */
    int (*in_func)();	/* 内部コマンド（関数） */
    char **arg_list;	/* 外部コマンドとオプションのリスト(NULL終端が必須) */

    struct command_list *next;
} command_list_t;

typedef struct mimetype_list {
    char *extension;
    char *mimetype;
    struct mimetype_list *next;
} mimetype_list_t;


/**
 * functions
 */
int msg_convert(GMimeObject *, GMimeObject **, harmless_proc_arg_t *);

char *read_harmlessconf(char *path, void **pointer);
void free_harmlessconf(command_list_t *);

char *read_mimetypes(char *path, void **pointer);
void free_mimetypes(mimetype_list_t *);

int convert_alternative();
int convert_multipart();
int convert_extension();
int convert_none();
extern char *is_readable_file(char *);

#endif		/* _MSG_CONVERT_H */
