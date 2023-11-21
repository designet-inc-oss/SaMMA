
#ifndef _EXEC_COMMAND_H
#define _EXEC_COMMAND_H

#include <gmime/gmime.h>
#include "sender_check.h"

#define ERR_EXEC_EXTERNAL_COMMAND "Failed to external command.: command=%s, ret=%d, source=%s, message-id=%s, sender=%s, rcpt=%s\n"

#define ERR_PIPE_READ             "%s: Failed to read from pipe.: (%s)"
#define ERR_PIPE_WRITE            "%s: Failed to write to pipe.: (%s)"

#define EXEC_EXTERNAL_FAILED  -1
#define EXEC_EXTERNAL_SUCCESS 0

#define ENV_FILENAME	"SAMMA_FILENAME"

char *parse_command(char *string, char ***list);
void free_arg_list(char **list);
int exec_external(GMimeObject *part, char **cmd_arg, char **output, size_t *output_len, sender_check_arg_t *data, int timeout, int next_msg);
extern char *is_executable_file(char *);

#endif		/* _EXEC_COMMAND_H */
