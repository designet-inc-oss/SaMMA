/*
 * samma
 * harmless.c
 *
 * switch convert, encrypt, delete
 */

#define _GNU_SOURCE 
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "log.h"
#include "mailzip_config.h.in"
#include "sender_check.h"
#include "exec_command.h"

#define R 0
#define W 1

void exec_sig_catch(int sig)
{
    exit(-1);
}

char *parse_command(char *string, char ***list)
{
    char **list_making;
    char *token;
    char *save;
    char *err;
    char *arg_list[256];	/* まあ引数FF個とか無いでしょう */
    int i, j;


    token = strtok_r(string, " \t", &save);

    err = is_executable_file(token);
    if (err) {
        return err;
    }

    arg_list[0] = token;

    for (token = strtok_r(NULL, " ", &save), i = 1;
         token != NULL;
         token = strtok_r(NULL, " ", &save), i++) {

        if (i > 256) {
            err = "Too many arguments(256)";
            return err;
        }
        arg_list[i] = token;
    }

    list_making = (char **)malloc(sizeof(char *) * (i + 1));
    for (j = 0; j < i; j++) {
        (list_making)[j] = strdup(arg_list[j]);
        if ((list_making)[j] == NULL) {
            err = "Cannot allocate memory";
            for (i = 0; i < j; i++)
                free((list_making)[i]);
            free(list_making);
            return err;
        }
    }

    // リストをNULL終端
    (list_making)[j] = NULL;

    *list = list_making;
    return NULL;
}


void free_arg_list(char **arg_list)
{
    int i;
    if (arg_list == NULL)
        return;

    // 1000個も引数ないだろうのでエラーで打ち止め
    for (i = 0; arg_list[i] != NULL; i++) {
        if (i > 1000) {
            log("free_arg_list(): list MUST be NULL terminated.");
            return;
        }
        free(arg_list[i]);
    }
}

/*
 * Args:
 *   cmd_arg                  command argument list
 *   input                    input string to feed external command
 *   input_size               size of input string
 *   output                   string of external command output
 *   output_size              size of external command output
 *   data                     required for logging
 * Returns:
 *   EXEC_EXTERNAL_FAILED     Failure: -1
 *   EXEC_EXTERNAL_SUCCESS    Success: 0
 *   ret(>0)                  exit status code of exec command.
 */
#define EX_BUFSIZE 4096
int
exec_external(GMimeObject *part, char **cmd_arg, char **output, size_t *output_len, sender_check_arg_t *data, int timeout, int msg_next)
{
    int c2p_pfd[2],p2c_pfd[2];
    size_t size_buf;
    char *tmp_output = NULL;
    char buf[EX_BUFSIZE];
    char *tmpout;
    int sum_size = 0;
    int sts = 0;
    int ret;
    pid_t pid;

    // 子プロセスに書き込むパイプ (pipe Parent-to-Child) を作る
    if (pipe2(p2c_pfd, O_CLOEXEC) < 0) {
        log(ERR_PIPE_CREATE, "pipe", strerror(errno));
        return EXEC_EXTERNAL_FAILED;
    }
    // 子プロセスから読み込むパイプ (pipe Child-to-Parent) を作る
    if (pipe2(c2p_pfd, O_CLOEXEC) < 0) {
        close(p2c_pfd[R]);
        close(p2c_pfd[W]);
        log(ERR_PIPE_CREATE, "pipe", strerror(errno));
        return EXEC_EXTERNAL_FAILED;
    }
    /* 子プロセス生成 */
    if((pid = fork()) < 0){
        close(p2c_pfd[R]);
        close(p2c_pfd[W]);
        close(c2p_pfd[R]);
        close(c2p_pfd[W]);
        log(ERR_FORK_CREATE, "fork", strerror(errno));
        return EXEC_EXTERNAL_FAILED;
    }
    //子プロセスの処理
    if(pid == 0){

        signal(SIGALRM, exec_sig_catch);
        alarm(timeout);

        close(p2c_pfd[W]);
        close(c2p_pfd[R]);
        dup2(p2c_pfd[R], 0);
        dup2(c2p_pfd[W], 1);

        close(p2c_pfd[R]);
        close(c2p_pfd[W]);

        // Execution
        execvp(cmd_arg[0], cmd_arg);
        exit(-1);
    }
    /*
     * 親プロセス
     */
    close(p2c_pfd[R]);
    close(c2p_pfd[W]);


    GMimeStream *w_stream = g_mime_stream_pipe_new(p2c_pfd[W]);

    GMimeDataWrapper *wrapper = g_mime_part_get_content_object((GMimePart *)part);

    g_mime_data_wrapper_write_to_stream(wrapper, w_stream);
    if (GMIME_IS_OBJECT(wrapper)) {
        g_object_unref(wrapper);
    }
    g_mime_stream_flush(w_stream);
    g_mime_stream_close(w_stream);
    g_object_unref(w_stream);


    // パイプを読み、バッファに書き出す
    while ((size_buf = read(c2p_pfd[R], buf, EX_BUFSIZE)) > 0) { 
        size_t current = sum_size;
        sum_size += size_buf;

        tmpout = realloc(tmp_output, sum_size + 1);
        if (tmpout == NULL) {
            free(tmp_output);
            close(c2p_pfd[R]);
            log(ERR_MEMORY_ALLOCATE, "exec_external", "output", strerror(errno));
            return EXEC_EXTERNAL_FAILED;
        }
        tmp_output = tmpout;
        memcpy(tmp_output + current, buf, size_buf);
        *(tmp_output + sum_size) = '\0';
    }
    if (size_buf < 0) {
        //read 失敗の時
        free(tmp_output);
        close(c2p_pfd[R]);
        log(ERR_PIPE_WRITE, "exec_external", strerror(errno));
        return EXEC_EXTERNAL_FAILED;
    }

    close(c2p_pfd[R]);

    // 子プロセスの終了を待つ
    ret = waitpid(pid, &sts, WUNTRACED);
    if (ret == -1) {
        log(ERR_WAIT_CHILD, "exec_external", strerror(errno));
        free(tmp_output);
        return EXEC_EXTERNAL_FAILED;
    }
    if (WIFEXITED(sts)) {       // return or exit //
        ret = WEXITSTATUS(sts); // exit code //
        if (ret != 0) {
            if (msg_next != 1) {
                log(ERR_EXEC_EXTERNAL_COMMAND, cmd_arg[0], ret, data->ip, data->message_id,
                    data->envelope_from, data->rcpt_to);
            }
            free(tmp_output);
            return ret;
        }
    } else {
        log(ERR_WAIT_CHILD, "exec_external", strerror(errno));
        free(tmp_output);
        return EXEC_EXTERNAL_FAILED;
    }

    if (sum_size < 1) {
        return EXEC_EXTERNAL_FAILED;
    }

    //正常時のみ、作成した文字列を **output に付け替える
    *output = tmp_output;
    *output_len = sum_size;

    return EXEC_EXTERNAL_SUCCESS;
}
