/*
 * samma
 *
 * Copyright (C) 2006,2007,2008 DesigNET, INC.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

/*
 * $RCSfile$
 * $Revision$
 * $Date$
 */

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <libdgstr.h>
#include <libdgmail.h>
#include <gmime/gmime.h>
#include "log.h"
#include "mailzip_config.h"
#include "maildrop.h"
#include "global.h"
#include "mailzip_tmpl.h"

/*
 * tmpl_read()
 *
 * Read the template file.
 *
 * Args:
 *   char **tmp      pointer
 *   char *tmp_file  file path
 *
 * Return value:
 *   SUCCESS	   0    success
 *   ERROR	   -1    error
 *
 */
int
tmpl_read(char **tmp, char *tmpl_file) 
{
    int fd, ret;
    char buf[BUFSIZE];
    char *tmpr = NULL;
    int total = 0;

    // open template file
    fd = open(tmpl_file, O_RDONLY);
    if (fd == -1) {
        log(ERR_FILE_OPEN, "tmpl_read", tmpl_file);
        return(ERROR);
    }

    // read template file
    do {

        ret = read(fd, buf, BUFSIZE - 1);
        if (ret == -1) {
            log(ERR_FILE_GET_INFO, "tmpl_read", tmpl_file);
	    if (*tmp != NULL) {
		free(*tmp);
		*tmp = NULL;
	    }
            close(fd);
            return(ERROR);
        } else if (ret != 0) {
            buf[ret] = '\0';

            tmpr = (char *)realloc(*tmp, (total + ret + 1));
            if (tmpr == NULL) {
                if (*tmp != NULL) {
                    free(*tmp);
		    *tmp = NULL;
                } 
                log(ERR_MEMORY_ALLOCATE, "tmpl_read", "tmpr", strerror(errno));
                close(fd);
                return(ERROR);
            }
            *tmp = tmpr;

            strcpy((*tmp + total), buf);
            total = total + ret;
	}

    } while (ret != 0);

    //file close
    close(fd);

    if (*tmp == NULL) {
        log(ERR_TEMPLATE_READ, "tmpl_read", tmpl_file);
#ifdef __CUSTOMIZE2018
        // mark empty information
    if (ismode_enc) {        
        *tmp = "";
    }
#endif	// __CUSTOMIZE2018
        return(ERROR);
    }

    return(SUCCESS);
}

/* split_strings
*
* separate strings to front part and back part.
* separater is selected by argument 3.
*
* Args:
*   char *str		separated strings
*   char **arg_front	store front part pointer
*   char **arg_back	store back part pointer
*   int sep		separator	
*
* Return value:
*   TRUE	     include multibyte characters
*   FALSE           not include
*
*/
int
split_strings(char *str, char **arg_front, char **arg_back, int sep)
{
    char *p = NULL;
    char *front = NULL;
    char *back = NULL;
    char *tmp = NULL;
    char *tmp_back = NULL;
    int size = 0;

    // check separator
    p = strrchr(str, sep);
    if (p == NULL) {
        return ERROR;
    }

    // if separator is found, copy strings not to distruct data
    front = strdup(str);
    if (front == NULL) {
        return ERROR;
    }

    // allocate memory for '\0'
    tmp = (char *)realloc(front, strlen(front) + 2);
    if (tmp == NULL) {
        return ERROR;
    }
    front = tmp;

    // size is length from separator to end of strings '\0'
    p = strrchr(front, sep);
    size = strlen(p) + 1;

    // separate header and body
    memmove(p + 1, p, size);
    *p = '\0';
    tmp_back = p + 1;

    // allocate memory for latter part
    tmp = (char *)calloc(strlen(tmp_back) + 1, sizeof(char) * 1);
    if (tmp == NULL) {
        free(front);
        return ERROR;
    }
    back = tmp;
    strcpy(back, tmp_back);

    // change addresses
    *arg_front = front;
    *arg_back = back;

    return SUCCESS;
}

/* trim_strings
 *
 * trim strings not to display spaces or tabs.
 *
 * Args:
 *   char **str trimed strings
 *
 * Return value:
 *
 * Type of this function is void.
 *
 */
#define IS_SPACE(pointer) ((pointer) == ' ' || (pointer) == '\t' || (pointer) == '\n')
void trim_strings(char **str)
{
    char *p = NULL;


    // memorize head pointer of rcpt
    p = *str;

    // search end of the strings from head
    while (*p != '\0' && IS_SPACE(*p)) {
        p++;
    }

    // copy the strings to the same buffer
    memmove(*str, p, strlen(p) + 1);

    // memorize tail pointer of rcpt
    p = *str + strlen(*str) - 1;

    // search end of strings from tail
    while (p >= *str && IS_SPACE(*p)) {
        p--;
    }

    // set '\0' to the end of the address
    *(p + 1) = '\0';

    return;
}

/* check_multibyte_char
*
* check whether strings include multibyte characters or not.
*
* Args:
*   char *str	checked strings
*
* Return value:
*   TRUE	     include multibyte characters
*   FALSE           not include
*
*/
int
check_multibyte_char(char *str)
{
    char kanji_in[] = {0x1B, 0x24, 0x42, 0x00};
    char kanji_out[] = {0x1B, 0x28, 0x42, 0x00};
    char *ret = NULL;

    // search kanji-IN and kanji-OUT
    if ((ret = strstr(str, kanji_in)) == NULL 
         && (ret = strstr(str, kanji_out)) == NULL) {
        return FALSE;
    }

    return TRUE;
}

/* check_addr
 *
 * check mail addresses include multibyte characters, '<' or '>
 *
 * Args:
 *    char *str		checked strings
 *
 * Return value:
 *    TRUE		include multibyte characters and "<>"
 *    FALSE		NOT include multibyte characters, '<' or '>'
 */
int check_addr(char *str)
{
    int ret = 0;
    char *retp = NULL;

    // check multibyte characters
    ret = check_multibyte_char(str);
    if (ret == FALSE) {
        return FALSE;
    }

    // check '<' and '>'
    if ((retp = strchr(str, '<')) == NULL)
    {
        return FALSE;
    }
    if (strchr(retp, '>') == NULL) {
        return FALSE;
    }

    return TRUE;

}

/* alloc_and_cat
 *
 * extend buffer and combine strings with the other strings
 *
 * Args:
 *   char *buf		combined strings(former part)
 *   int  arg_num 	the number of arguments
 *   ... 		combined strings <extendable arguments>
 *
 * Return values:
 *   SUCCESS	memory is allocated
 *   ERROR	memory is not allocated
 */
int alloc_and_cat(char **buf, int arg_num, ...)
{
    char *arg_str = NULL;
    char *tmp = NULL;
    int i = arg_num + 1;
    int cnt = 1;

    // extendable arguments
    va_list args;
    va_start(args, arg_num);

    // loop until all arguments put into tmpbuf
    for (i = arg_num + 1; cnt != i; cnt++) {

        // set argument strings
        arg_str = va_arg(args, char *);

        // check argument buffer size
        if (*buf == NULL) {
           tmp  = (char *)calloc(strlen(arg_str) + 1, sizeof(char));
        } else {
           tmp  = (char *)realloc(*buf, strlen(*buf) + strlen(arg_str) + 1);
        }
        if (tmp == NULL) {
            return ERROR;
        }
        *buf = tmp;

        // combine buf with str
        strcat(*buf, arg_str);
        strcat(*buf, "\0");
    }

    va_end(args);

    return SUCCESS;
}

/* str_jis_divide
 *
 * divide ISO-2022-jp strings to encode mime
 *
 * Args:
 *   char *org_str	original strings of ISO-2022-JP
 *   char **div_str	divided strings
 *   char *rest_len	length of strings
 *   int **flag		memorizing kanji-IN is exist or not
 *
 * Return value:
 *   i	length of divided strings
 */
/*
 * max length after encoding strings - part of form = 75 - 18 = 58bytes
 * => max length of converting to ISO-2022-JP = 58 * 3/4 = 42bytes
 */
#define DIVIDE_JIS_LEN ((75 - strlen(MIME_TOPSTR) - strlen(MIME_LASTSTR)) * 3/4)
int
str_jis_divide(char *org_str, char *div_str, int rest_len, int **flag)
{
    int o_cnt = 0;
    int d_cnt = 0;

    // line_len is possible length of encoding
    int line_len = DIVIDE_JIS_LEN; 
    int k_in = FALSE;
    
    k_in = **flag;

    // strings includes multibyte characters but kanji_IN is not exist
    if (k_in == TRUE) {

        // store kanji_IN
        div_str[0] = 0x1B;
        div_str[1] = 0x24;
        div_str[2] = 0x42;

        d_cnt += 3;
        line_len -= 3;
    }

    // loop until length of divided strings over maximum length of one line
    while (line_len > 0 && rest_len >= o_cnt) {

        // end of strings is found, get out of this loop
        if (org_str[o_cnt] == '\0') {
            break;
        }
        // kanji-IN is found
        if (org_str[o_cnt] == 0x1B && org_str[o_cnt + 1] == 0x24
            && org_str[o_cnt + 2] == 0x42) {

            // rest buffer is not enough
            if (line_len < 8) {
                break;

            } else {
                // store kanji-IN
                div_str[d_cnt] = org_str[o_cnt];
                div_str[d_cnt + 1] = org_str[o_cnt + 1];
                div_str[d_cnt + 2] = org_str[o_cnt + 2];
                d_cnt += 3;
                o_cnt += 3;
                line_len -= 3;
                k_in = TRUE;
            }

        // kanji-OUT is found
        } else if (org_str[o_cnt] == 0x1B && org_str[o_cnt + 1] == 0x28
                   && org_str[o_cnt + 2] == 0x42) {

            // store kanji-OUT
            div_str[d_cnt] = org_str[o_cnt];
            div_str[d_cnt + 1] = org_str[o_cnt + 1];
            div_str[d_cnt + 2] = org_str[o_cnt + 2];

            o_cnt += 3;
            d_cnt += 3;
            line_len -= 3;
            k_in = FALSE;

        // case multibyte
        } else if (k_in == TRUE) {

            // rest buffer is not enough
            if (line_len < 5) {
                div_str[d_cnt] = 0x1B;
                div_str[d_cnt + 1] = 0x28;
                div_str[d_cnt + 2] = 0x42;

                d_cnt += 3;
                break;

            // rest buffer is enough
            } else {
                div_str[d_cnt] = org_str[o_cnt];
                div_str[d_cnt + 1] = org_str[o_cnt + 1];
                d_cnt += 2;
                o_cnt += 2;
                line_len -= 2;
            }

        // case ASCII
        } else {
            // rest buffer is not enough
            if (line_len < 1) {
                break;

            // rest buffer is enough
            } else {
                div_str[d_cnt] = org_str[o_cnt];
                d_cnt += 1;
                o_cnt += 1;
                line_len -= 1;
            }
        }
    }

    div_str[d_cnt] = '\0';
    **flag = k_in;

    return o_cnt;
}

/* encode_mime_from_jis
 *
 * mime encode strings of ISO-2022-JP
 *
 * Args:
 *   char *jis_str	strings of ISO-2022-JP
 *
 * Return value:
 *   enc_str		mime encoded strings
 *
 */

#define ENC_FORMSIZE (strlen(MIME_TOPSTR) + strlen(MIME_LASTSTR) + 3)
char *
encode_mime_from_jis(char *jis_str)
{
    char *enc_str = NULL;
    char *tmp_str= NULL;
    char *tmp_enc = NULL;
    char buf[JIS_STR_MAX_LEN];
    char *p = jis_str;
    int ret = 0;
    int cnt = 0;
    int tmp = FALSE;
    int *k_in = NULL;

    k_in = &tmp;

    // check length of argument strings
    if (strlen(jis_str) == 0) {
        // copy strings '\0'
        enc_str = strdup(p);
        if (enc_str == NULL) {
            log(ERR_MEMORY_ALLOCATE, "encode_mime_from_jis", "tmp_str",
                strerror(errno));
            return NULL;
        }
        return enc_str;
    }

    // loop until all characters are encoded
    do {
        // if no strings of encoding, get out of this loop
        cnt = str_jis_divide(p, buf, strlen(p), &k_in);
        if (cnt == 0) {
            break;
        }

        // allocate memory for temporary buffer
        tmp_str = (char *)calloc(strlen(buf) + 1, sizeof(char));
        if (tmp_str == NULL) {
            log(ERR_MEMORY_ALLOCATE, "encode_mime_from_jis", "tmp_str",
                strerror(errno));
            return NULL;
        }

        // copy strings for encoding
        memcpy(tmp_str, buf, strlen(buf) + 1);

        // strings NOT include multibyte characters
        if (check_multibyte_char(tmp_str) == FALSE) {
            tmp_enc = tmp_str;

            // allocate memory and put NOT multibyte character strings
            ret = alloc_and_cat(&enc_str, 3, " ", tmp_enc, "\n");
            if (ret == ERROR) {
                if (enc_str != NULL) {
                    free(enc_str);
                }
                log(ERR_MEMORY_ALLOCATE, "encode_mime_from_jis", "enc_str",
                    strerror(errno));
                return NULL;
            }

        // strings include multibyte characters
        } else {

            // mime encode
            tmp_enc = encode_b64(tmp_str);
            free(tmp_str);
            if (tmp_str == NULL) {
                log(ERR_MEMORY_ALLOCATE, "encode_mime_from_jis", "tmp_enc",
                    strerror(errno));
                return NULL;
            }

            // make MIME strings
            ret = alloc_and_cat(&enc_str, 5, " ", MIME_TOPSTR, tmp_enc,
                                MIME_LASTSTR, "\n");
            free(tmp_enc);
            if (ret == ERROR) {
                if (enc_str == NULL) {
                    free(enc_str);
                }
                log(ERR_MEMORY_ALLOCATE, "encode_mime_from_jis", "tmp_enc",
                    strerror(errno));

                return NULL;
            }

        }
        // check size of rest strings
        p += cnt; 

    } while (strlen(p) > 0);

    return enc_str;
}

/* get_one_addr
 *
 * If header"To" has some addresses, split them and remove spaces or tabs.
 *
 * Args:
 *   char *addr		pointer of address
 *   char *rest_addr	addresses still not refered and pointing ','
 *
 * Return value:
 *   SUCCESS		succeed of separating and triming
 *   NO_REST		no rest address
 */
#define NO_REST 2
int
get_one_addr(char **addr, char **rest_addr)
{

    // if ',' is not found, return
    if ((*rest_addr = strchr(*addr, ',')) == NULL) {
        return NO_REST;
    }

    // ',' is replaced to '\0'
    **rest_addr = '\0';

    // memorize rest addresses pointer
    *rest_addr += 1;

    return SUCCESS;
}

/* encode_addr
 *
 * If header"To" or header"From" includes multibyte characters,
 * encode them. Addresses are not encoded.
 *
 * Args:
 *   char *str		strings of header "To" or "From"
 *                      "To: " or "From: " is needed to separate
 * Return value:
 *   encoded_str	encoded "To" or "From" strings
 *
 */
char *
encode_addr(char *str)
{
    char *name_part = NULL;
    char *addr_part = NULL;
    char *enc_str = NULL;
    char *tmp = NULL;
    int ret = 0;

    // separate name part and addr part
    ret = split_strings(str, &name_part, &addr_part, '<');
    if (ret == ERROR) {
        log(ERR_MEMORY_ALLOCATE, "encode_addr", "str",
            strerror(errno));
        if (name_part != NULL) {
            free(name_part);
        }
        if (addr_part != NULL) {
            free(addr_part);
        }
        return NULL;
    }

    // trim name part and addr part
    trim_strings(&name_part);
    trim_strings(&addr_part);

    // store name_part
    enc_str = encode_mime_from_jis(name_part);
    free(name_part);
    if (enc_str == NULL) {
        return NULL;
    }
    // store addr_part : 2 = ' ' + '\0'
    tmp = (char *)realloc(enc_str,
                          strlen(enc_str) + strlen(addr_part) + 2);
    // allocate error
    if (tmp == NULL) {
        free(addr_part);
        free(enc_str);
        return NULL;
    }
    enc_str = tmp;

    // combine name part and addr part
    ret = alloc_and_cat(&enc_str, 2, " ", addr_part);
    free(addr_part);
    if (ret == ERROR) {
        log(ERR_MEMORY_ALLOCATE, "encode_addr", "enc_str",
            strerror(errno));
        free(enc_str);
        return NULL;
    }

    return enc_str;
}

/* encode_addr_field
 *
 * If header"To" or header"From" includes multibyte characters,
 * encode them and store buffer.
 *
 * Args:
 *   char *field	strings of header "To" or "From"
 *   char **str		encoded strings is stored
 *
 * Return value:
 *   SUCCESS		encoding is suceed
 *   ERROR		encoding is failed or cannot allocate memory
 */
int
encode_addr_field(char *field, char **buf, char *f_name)
{
    char *enc = NULL;
    char *addr_p = NULL;
    char *rest_p = NULL;
    int ret = 0;

    // set the field name to buffer
    ret = alloc_and_cat(buf, 1, f_name);
    if (ret == ERROR) {
        log(ERR_MEMORY_ALLOCATE, "encode_addr_field", "buf",
            strerror(errno));
        return ERROR;
    }

    // memorize head of argument field
    addr_p = field;

    // loop until add buffer to all of addresses in the field
    while(get_one_addr(&addr_p, &rest_p) != NO_REST) {

        // trim the address
        trim_strings(&addr_p);

        // check if addresses include multibyte characters , '<' and '>'
        if (check_addr(addr_p) == FALSE) {

            // set ' ' and copy strings
            ret = alloc_and_cat(&enc, 2, " ", addr_p);
            if (ret == ERROR) {
                if (enc != NULL) {
                    free(enc);
                }
                return ERROR;
            }

        } else {

            // if addresses include multibytes and "<>", encode strings
            enc = encode_addr(addr_p);
            if (enc == NULL) {
                return ERROR;
            }
        }

        // put the encoded address into the buffer
        ret = alloc_and_cat(buf, 3, enc, ",", "\n");
        free(enc);
        enc = NULL;
        if (ret == ERROR) {
            log(ERR_MEMORY_ALLOCATE, "encode_addr_field", "buf",
                strerror(errno));
            return ERROR;
        }

        // addr_p points head of rest addresses
        addr_p = rest_p;
    }

    // trim the address
    trim_strings(&addr_p);

    // strings don't include multibyte characters , '<' or '>'
    if (check_addr(addr_p) == FALSE) {

        // set ' ' after field name and copy strings
        ret = alloc_and_cat(buf, 3, " ", addr_p, "\n");
        if (ret == ERROR) {
            log(ERR_MEMORY_ALLOCATE, "encode_addr_field", "enc",
                strerror(errno));
            return ERROR;
        }

    // strings include multybyte characters
    } else {

        // encode strings
        enc = encode_addr(addr_p);
        if (enc == NULL) {
            return ERROR;
        }

        // add buffer to the encoded address
        ret = alloc_and_cat(buf, 2, enc, "\n");
        free(enc);
        if (ret == ERROR) {
            log(ERR_MEMORY_ALLOCATE, "encode_addr_field", "buf",
                strerror(errno));
            return ERROR;
        }
    }

    return SUCCESS;
}

/* encode_subject_field
 *
 * If header subject includes multibyte characters, encode them
 * and store to buffer.
 *
 * Args:
 *   char *field	strings of header subject
 *   char **str		encoded strings is stored
 *
 * Return value:
 *   SUCCESS		encoding is suceed
 *   ERROR		encoding is failed or cannot allocate memory
 */
#define H_SUBJ 		"Subject:"
#define SUBJ_SIZE 	8
int
encode_subject_field(char *field, char **buf)
{
    char *p = field;
    char *enc = NULL;
    int ret = 0;

    // put buffer into strings "Subject:"
    ret = alloc_and_cat(buf, 1, H_SUBJ);
    if (ret == ERROR) {
        log(ERR_MEMORY_ALLOCATE, "encode_subject_field", "buf",
            strerror(errno));
        return ERROR;
    }

    // trim subject
    trim_strings(&p);

    // encode strings
    enc = encode_mime_from_jis(p);
    if (enc == NULL) {
        return ERROR;
    }

    // add buffer to subject field
    ret = alloc_and_cat(buf, 1, enc);
    free(enc);
    if (ret == ERROR) {
        log(ERR_MEMORY_ALLOCATE, "encode_subject_field", "buf",
            strerror(errno));
        return ERROR;
    }

    return SUCCESS;
}

/* encode_tmplheader
 *
 * encode header of mail template
 *
 * Args:
 *   char **mail     template file data
 *
 * Return:
 *   ERROR		-1   error
 *   SUCCESS		0   success
 *
 */
#define H_TO 		"To:"
#define H_FROM 		"From:"
#define TO_SIZE		3
#define FROM_SIZE       5	
int
encode_tmplheader(char **mail)
{
    char *tmp = NULL;
    char *header = NULL;
    char *one_line = NULL;
    char *p = NULL;
    char *header_p = NULL;
    char *body = NULL;
    int ret = 0;

    // check if template format is correct or not
    if ((body = strstr(*mail, MAIL_SEP)) == NULL) {
        // case not correct
        return SUCCESS;
    }

    // header pointer of mail is the same of **mail
    header_p = *mail;
    // memorize head of body part
    body = body + 1;

    // loop until header is end
    while (header_p != body) {

        // check each line
        one_line = get_field(header_p, &p);
        if (one_line == NULL) {
            log(ERR_MEMORY_ALLOCATE, "get_field", "one_line",
                strerror(errno));
            if (header != NULL) {
                free(header);
            }
            return ERROR;
        }

        // case field is "To:"
        if (strncasecmp(one_line, H_TO, TO_SIZE) == 0) {

            // encode to field
            ret = encode_addr_field(one_line + TO_SIZE, &header, H_TO);

        // case field is "From: "
        } else if (strncasecmp(one_line, H_FROM, FROM_SIZE) == 0) {

            // encode from field
            ret = encode_addr_field(one_line + FROM_SIZE, &header, H_FROM);

        // case field is "Subject: "
        } else if (strncasecmp(one_line, H_SUBJ, SUBJ_SIZE) == 0) {

            // encode subject field
            ret = encode_subject_field(one_line + SUBJ_SIZE, &header);


        // other header field
        } else {
            ret = alloc_and_cat(&header, 2, one_line, "\n");
        }
        free(one_line);

        // check error
        if (ret == ERROR) {
            log(ERR_MEMORY_ALLOCATE, "encode_tmplheader", "header",
                strerror(errno));
            if (header != NULL) {
                free(header);
            }
            return ERROR;
        }

        // pass the next field pointer
        header_p = p;
    }

    // extend memory to joint header, body and '\0'
    tmp = (char *)realloc(*mail, strlen(*mail) + strlen(header) + 2);
    if (tmp == NULL) {
        log(ERR_MEMORY_ALLOCATE, "encode_tmplheader", "mail",
            strerror(errno));
        free(header);
        return ERROR;
    }
    *mail = tmp;

    // search again head of body part
    body = strstr(*mail, "\n\n") + 1;

    // move body part backward to put header part
    memmove(*mail + strlen(header), body, strlen(body) + 1);

    // put header part forward body part
    memcpy(*mail, header, strlen(header));
    free(header);

    return SUCCESS;
}

#define NOSUBJECT	""
/*
 * tmpl_tag_replace()
 *
 * Args:
 *   char *           read file data
 *   struct mailzip   reference data
 *   struct rcptinfo  reference data
 *   char *           recipient address
 *   char **          replaced date
 *   int              if mode is NOTICEPASS_FROM, in mailbody repalace <@@RCPTLIST@@> by *rcptinfo
 *                    if mode is NOTICEPASS_TO, in mailbody repalace <@@RCPTLIST@@> by *sender
 *   char *           envfrom address
 *
 * Return:
 *   ERROR		-1   error
 *   SUCCESS		0   success
 */
int
tmpl_tag_replace(char *tmp, struct mailzip mz, struct rcptinfo *other, char *sender, char **retp, 
                int mode, char *envfrom)
{

    int i;
    char *subject = NULL;
    char *filename = NULL;
    char *tmpl = NULL;
    char *rcptaddr, *tmpp = NULL, *tmptagp = NULL;
    int ret = 0, total = 0;
    int rcptaddr_len = 0;
    char *name, *tmpf = NULL;
    int name_len = 0, ret_len = 0, total_len = 0;
    int tagnum = 0;

    struct rcptinfo *p;

    /* Repairing for encoded Subject by MIME encode(2014/05/14(wed)) */
    char *tmp_dec = NULL;

    struct strtag tmpl_tag[] = {
        {"SUBJECT", 7, NULL},
        {"DATE", 4, NULL},
        {"PASSWORD", 8, NULL},
        {"RCPTLIST", 8, NULL},
        {"FILENAME", 8, NULL},
        {"TOADDR", 6, NULL},
        {"ENVFROM", 7, NULL}
    };
    tagnum = sizeof(tmpl_tag) / sizeof(struct strtag);

    // set subject
    if (mz.subject != NULL) {
	if (dg_str2code_replace((char *)mz.subject, &subject, STR_UTF8, STR_JIS) != 0) {
            log(ERR_CHARCODE_CONVERT, "tmpl_tag_replace");
            subject = strdup(NOT_ENC_SUBJECT);
	    if (subject == NULL) {
            log(ERR_MEMORY_ALLOCATE, "tmpl_tag_replace", "subject", strerror(errno));
		return(ERROR);
	    }
	}
        tmpl_tag[SUBJECT].st_str = subject;
    } else {
        tmpl_tag[SUBJECT].st_str = NOSUBJECT;
    }

    // set date
    tmpl_tag[DATE].st_str = mz.date;

    // set passwd
    tmpl_tag[PASSWORD].st_str = other->passwd;

    // set toaddr(sender address)
    tmpl_tag[TOADDR].st_str = sender;

    // set envfrom(sender address)
    tmpl_tag[ENVFROM].st_str = envfrom;

    // rcptaddr total length
    for (p = other; p != NULL; p = p->Next) {
        for (i = 0; (p->rcptlist + i)->rcpt_addr != NULL; i++) {
            rcptaddr_len = (p->rcptlist + i)->rcpt_addr_len;
            ret += rcptaddr_len + 1;
        }
    }

    // allocate memory
    tmpp = (char *)malloc(ret + 1);
    if (tmpp == NULL) {
        log(ERR_MEMORY_ALLOCATE, "tmpl_tag_replace", "tmpp", strerror(errno));
	if (subject != NULL) {
	    free(subject);
	    subject = NULL;
	}
        return(ERROR);
    }

    // reset memory
    *tmpp = '\0';

    for (p = other; p != NULL; p = p->Next) {
        // write memory
        for (i = 0; (p->rcptlist + i)->rcpt_addr != NULL; i++) {
            rcptaddr = (p->rcptlist + i)->rcpt_addr;
            rcptaddr_len = (p->rcptlist + i)->rcpt_addr_len;

            strcat(tmpp, rcptaddr);
            *(tmpp + total + rcptaddr_len) = '\n';
            *(tmpp + total + rcptaddr_len + 1) = '\0';
            total = total + rcptaddr_len + 1;
        }
    }

    // last '\n' change into '\0'
    *(tmpp + total - 1) = '\0';

    if (mode == NOTICEPASS_FROM) {
        // store all rcptaddr 
        tmpl_tag[RCPTLIST].st_str = tmpp;
    } else {
        // store all rcptaddr 
        tmpl_tag[RCPTLIST].st_str = sender;
    }

    //file_name
    if (mz.namelist != NULL) {
        for (i = 0; (mz.namelist + i)->attach_name != NULL; i++) {
            // total length
            ret_len = ret_len + (mz.namelist + i)->attach_name_len + 1;
        }
        // allocate memory
        tmpf = (char *)malloc(ret_len + 1);
        if (tmpf == NULL) {
            log(ERR_MEMORY_ALLOCATE, "tmpl_tag_replace", "tmpf", strerror(errno));
	    free(tmpp);
	    if (subject != NULL) {
	        free(subject);
	    }
            return(ERROR);
        }
        // reset memory
        *tmpf = '\0';
    } else {
        log(ERR_NULL_FILE_NAME, "tmpl_tag_replace");    
	free(tmpp);
	if (subject != NULL) {
	    free(subject);
	}
        return(ERROR);
    }

    // write memory
    for (i = 0; (mz.namelist + i)->attach_name != NULL; i++) {
        name = (mz.namelist + i)->attach_name;
        name_len = (mz.namelist + i)->attach_name_len;

        strcat(tmpf, name);
        *(tmpf + total_len + name_len) = '\n';
        *(tmpf + total_len + name_len + 1) = '\0';
        total_len = total_len + name_len + 1;
    }

    // last '\n' change into '\0'
    *(tmpf + total_len - 1) = '\0';
    // store all filename 
    if (dg_str2code_replace(tmpf, &filename, STR_UTF8, STR_JIS) != 0) {
        log(ERR_CHARCODE_CONVERT, "tmpl_tag_replace");
	filename = strdup(NOT_ENC_ATTACHFILE);
	if (filename == NULL) {
	    free(tmpp);
	    if (subject != NULL) {
		free(subject);
	    }
	    free(tmpf);
            log(ERR_MEMORY_ALLOCATE, "tmpl_tag_replace", "filename", strerror(errno));
	    return(ERROR);
	}
    }
    tmpl_tag[FILENAME].st_str = filename;
    free(tmpf);

    /* Repairing for encoded Subject by MIME encode(2014/05/14(wed)) */
    /* If Subject is encoded by MIME encode, change to not encoded strings.
     * Non-encoded strings are not processed.
     */
    tmp_dec = decode_mime(tmp);
    if (tmp_dec == NULL) {
        log(ERR_MEMORY_ALLOCATE, "tmpl_tag_replace of decode_mime", 
            "tmp_dec", strerror(errno));
        return(CONVERT_ERROR);
    }

    /* Repairing for encoded Subject by MIME encode(2014/05/14(wed)) */
    if (dg_str2code_replace(tmp_dec, &tmpl, STR_UTF8, STR_JIS) != 0) {
        log(ERR_CHARCODE_CONVERT, "tmpl_tag_replace");
        free(tmpp);
        free(tmp_dec);

        if (subject != NULL) {
            free(subject);
        }
        free(filename);

        return(CONVERT_ERROR);
    }

    /* Repairing for encoded Subject by MIME encode(2014/05/14(wed)) */
    free(tmp_dec);

    //replace tag
    tmptagp = str_replace_tag(tmpl, STARTTAG, ENDTAG, tmpl_tag, tagnum);
    // resouce free
    free(tmpp);
    if (subject != NULL) {
	free(subject);
    }
    free(filename);
    free(tmpl);

    // str_replace_tag error check
    if (tmptagp == NULL) {
        log(ERR_MEMORY_ALLOCATE, "tmpl_tag_replace", "tmptagp", strerror(errno));
        return(ERROR);
    }

    //convert str code
    if (dg_str2code_replace(tmptagp, retp, STR_UTF8, STR_JIS) != 0) {
        log(ERR_CHARCODE_CONVERT, "tmpl_tag_replace");
        free(tmptagp);
        return(CONVERT_ERROR);
    }
    free(tmptagp);


    // mime encode header from, rcpt and subject
    ret = encode_tmplheader(retp);
    if (ret == ERROR) {
        log(NOT_ENC_TMPL, "tmpl_tag_replace");
        free(*retp);
        return(CONVERT_ERROR);
    }

    return(SUCCESS);
}

/*
 * tmpl_tag_replace_noconv()
 *   read new template file and replace tags without converting
 *
 * Args:
 *   struct mailzip   reference data
 *   struct rcptinfo  reference data
 *   char *           recipient address
 *   char **          replaced date
 *   char *           convert-error template file path
 *   int              if mode is NOTICEPASS_FROM, in mailbody repalace <@@RCPTLIST@@> by *rcptinfo
 *                    if mode is NOTICEPASS_TO, in mailbody repalace <@@RCPTLIST@@> by *sender
 *
 * Return:
 *   ERROR		-1   error
 *   SUCCESS		0   success
 */
int
tmpl_tag_replace_noconv(struct mailzip mz, struct rcptinfo *other, 
                        char *sender, char **retp, char *filepath,
                        int mode)
{
    int i;
    char *rcptaddr, *tmpp = NULL, *tmptagp = NULL;
    int ret = 0, total = 0;
    int rcptaddr_len = 0;
    char *name, *tmpf = NULL;
    int name_len = 0, ret_len = 0, total_len = 0;
    int tagnum = 0;
    char *template = NULL;

    struct rcptinfo *p;

    struct strtag tmpl_tag[] = {
        {"SUBJECT", 7, NULL},
        {"DATE", 4, NULL},
        {"PASSWORD", 8, NULL},
        {"RCPTLIST", 8, NULL},
        {"FILENAME", 8, NULL},
        {"TOADDR", 6, NULL}
    };
    tagnum = sizeof(tmpl_tag) / sizeof(struct strtag);

    // set subject without encoding
    tmpl_tag[SUBJECT].st_str = (char *)mz.subject;

    // set date
    tmpl_tag[DATE].st_str = mz.date;

    // set passwd
    tmpl_tag[PASSWORD].st_str = other->passwd;

    // set toaddr(sender address)
    tmpl_tag[TOADDR].st_str = sender;

    for (p = other; p != NULL; p = p->Next) {
        // rcptaddr total length
        for (i = 0; (other->rcptlist + i)->rcpt_addr != NULL; i++) {
            rcptaddr_len = (other->rcptlist + i)->rcpt_addr_len;
            ret += rcptaddr_len + 1;
        }
    }

    // allocate memory
    tmpp = (char *)malloc(ret + 1);
    if (tmpp == NULL) {
        log(ERR_MEMORY_ALLOCATE, "tmpl_tag_replace_noconv", "tmpp", strerror(errno));
        return(ERROR);
    }

    // reset memory
    *tmpp = '\0';

    for (p = other; p != NULL; p = p->Next) {
        // write memory
        for (i = 0; (p->rcptlist + i)->rcpt_addr != NULL; i++) {
            rcptaddr = (p->rcptlist + i)->rcpt_addr;
            rcptaddr_len = (p->rcptlist + i)->rcpt_addr_len;

            strcat(tmpp, rcptaddr);
            *(tmpp + total + rcptaddr_len) = '\n';
            *(tmpp + total + rcptaddr_len + 1) = '\0';
            total = total + rcptaddr_len + 1;
        }
    }

    // last '\n' change into '\0'
    *(tmpp + total - 1) = '\0';

    if (mode == NOTICEPASS_FROM) {
        // store all rcptaddr 
        tmpl_tag[RCPTLIST].st_str = tmpp;
    } else {
        // store all rcptaddr 
        tmpl_tag[RCPTLIST].st_str = sender;
    }

    //file_name
    if (mz.namelist != NULL) {
        for (i = 0; (mz.namelist + i)->attach_name != NULL; i++) {
            // total length
            ret_len = ret_len + (mz.namelist + i)->attach_name_len + 1;
        }

        // allocate memory
        tmpf = (char *)malloc(ret_len + 1);
        if (tmpf == NULL) {
            log(ERR_MEMORY_ALLOCATE, "tmpl_tag_replace_noconv", "tmpf", strerror(errno));
            free(tmpp);

            return(ERROR);
        }
        // reset memory
        *tmpf = '\0';
    } else {
        log(ERR_NULL_FILE_NAME, "tmpl_tag_replace_noconv");    
        free(tmpp);
        return(ERROR);
    }

    // write memory
    for (i = 0; (mz.namelist + i)->attach_name != NULL; i++) {
        name = (mz.namelist + i)->attach_name;
        name_len = (mz.namelist + i)->attach_name_len;

        strcat(tmpf, name);
        *(tmpf + total_len + name_len) = '\n';
        *(tmpf + total_len + name_len + 1) = '\0';
        total_len = total_len + name_len + 1;
    }

    // last '\n' change into '\0'
    *(tmpf + total_len - 1) = '\0';

    // store all filename 
    tmpl_tag[FILENAME].st_str = tmpf;

    // read convert-error template file 
    if (tmpl_read(&(template), filepath) != 0) {
        free(tmpp);
        free(tmpf);
        return(ERROR);
    }

    // replace tag
    tmptagp = str_replace_tag(template, STARTTAG, ENDTAG, tmpl_tag, tagnum);
    // resouce free
    free(tmpp);
    free(tmpf);
    free(template);

    // str_replace_tag error check
    if (tmptagp == NULL) {
        log(ERR_MEMORY_ALLOCATE, "tmpl_tag_replace_noconv", "tmptagp", strerror(errno));
        return(ERROR);
    }

    *retp = tmptagp;

    return(SUCCESS);
}
