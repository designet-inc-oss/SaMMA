/*
 * samma
 * sender_check.c
 *
 * To do SPF check or Sender-IP check or something
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <spf2/spf.h>
#include <unistd.h>

#include "log.h"
#include "mailzip.h"
#include "sender_check.h"
#include "maildrop.h"
#include "global.h"

/**
 * static functions decraretion
 */
static int check_spf(sender_check_arg_t *data);
static int check_senderip(sender_check_arg_t *data);
static int check_senderdomain(sender_check_arg_t *data);
static int check_none(sender_check_arg_t *data);
int concatenate_rcpt(struct rcptinfo *rdmpasslist, char **rcptstr);

int comp_ipaddr(char *, sender_check_arg_t *data);
int comp_mx(char *, sender_check_arg_t *data);
int comp_ipaddr_ipv4(char *, struct in_addr *);
int comp_ipaddr_ipv6(char *, struct in6_addr *);

int comp_domain(char *, char *);
typedef struct _item_func {
    char *item;
    int (*function)();
} item_func_t;

item_func_t sendercheck_func_list[] = {
    { "check-spf", check_spf },
    { "check-senderip", check_senderip },
    { "check-senderdomain", check_senderdomain },
    { "none", check_none },
};

#define FUNC_LIST_SIZE (sizeof(sendercheck_func_list) / sizeof(item_func_t))


/**
 * set check functions to cf_entry
 */
char *set_sender_checker(char *setting, void **pointer)
{
    sender_check_functions_t *list = NULL, *list_end = NULL;
    char *target = setting;
    char *comma = NULL;
    int i, loop_flag;

    static char errbuf[1024];

    for (loop_flag = 1; loop_flag; target = comma + 1) {
        sender_check_functions_t *list_elem = NULL;

        // カンマを探し、見つかったら\0に置き換える。
        // 見つからなかったら、この周を終えたらループを抜ける
        comma = strchr((const char *)target, ',');
        if (comma != NULL) {
            *comma = '\0';
        } else {
            loop_flag = 0;
        }

        while (isblank(*target)) {
            target++;
        }
        // 項目を検査し、正しい項目だったらチェック関数をセットする
        for (i = 0; i < FUNC_LIST_SIZE; i++) {
            if (strcasecmp(sendercheck_func_list[i].item, target)) {
                continue;
            }

            list_elem = calloc(1, sizeof(sender_check_functions_t));
            if (list_elem == NULL) {
                free_sender_checker(list);
                sprintf(errbuf, SC_ERR_MEM, strerror(errno));
                return (errbuf);
            }

            list_elem->function = sendercheck_func_list[i].function;
            list_elem->next = NULL;

            // リストの末尾を更新しながらリストを長くする
            if (list == NULL) {
                list = list_elem;
                list_end = list_elem;
            } else {
                list_end->next = list_elem;
                list_end = list_elem;
            }

            break;
        }

        // ループが全部回った = ヒットしなかった
        if (i == FUNC_LIST_SIZE) {
            free_sender_checker(list);
            sprintf(errbuf, SC_ERR_INVALID, target);
            return (errbuf);
        }
    }

    *pointer = list;

    return NULL;
}

void free_sender_checker(sender_check_functions_t *list)
{
    sender_check_functions_t *tmp = list;

    while (list != NULL) {
        tmp = list->next;
        free(list);
        list = tmp;
    }
}

/**
 * milterから呼ばれる判定関数
 */
int check_sender(struct mlfiPriv *priv)
{
    int ret;
    sender_check_arg_t *data = &(priv->mlfi_sendercheck_arg);
    sender_check_functions_t *c_func = NULL;
    struct config *cfg = priv->mlfi_conf;

    if (data->ip == NULL) {
        return SENDER_CHECK_NG;
    }

    if (priv->mlfi_rdmpasslist == NULL) {
        return SENDER_CHECK_ERR;
    }

    ret = concatenate_rcpt(priv->mlfi_rdmpasslist, &(data->rcpt_to));
    if (ret < 0) {
        return SENDER_CHECK_ERR;
    }

    for (c_func = cfg->cf_sendercheck; c_func != NULL; c_func = c_func->next) {
        ret = (c_func->function)(data);
        switch (ret) {
            case SENDER_CHECK_OK:
            case SENDER_CHECK_NONE:
            case SENDER_CHECK_ERR:
                return ret;
            case SENDER_CHECK_NG:
                continue;
            default:
                return SENDER_CHECK_ERR;
        }
    }

    return SENDER_CHECK_NG;
}



/**
 * args:
 *
 * ret:
 * SENDER_CHECK_OK
 * SENDER_CHECK_NG
 * SENDER_CHECK_ERR
 */
int check_spf(sender_check_arg_t *data)
{
    SPF_server_t   *spf_server = NULL;
    SPF_request_t  *spf_request = NULL;
    SPF_response_t *spf_response = NULL;
    SPF_result_t result;

    spf_server = SPF_server_new(SPF_DNS_CACHE, 0);
    if (spf_server == NULL) {
        log("SPF_server_new failed.\n");
        return SENDER_CHECK_ERR;
    }

    spf_request = SPF_request_new(spf_server);
    if (spf_request == NULL) {
        SPF_server_free(spf_server);
        log("SPF_request_new failed.\n");
        return SENDER_CHECK_ERR;
    }

    if (data->af == AF_INET) {
        SPF_request_set_ipv4(spf_request, (data->sa).sa_in.sin_addr);
    } else {
        SPF_request_set_ipv6(spf_request, (data->sa).sa_in6.sin6_addr);
    }

    // SMTPでHELOコマンドが受信されなかった場合、NULLが来る
    // SPF_request_set_なんとか()にNULLを渡すとコアダンプ終了する
    if (data->helo != NULL) {
        if (SPF_request_set_helo_dom(spf_request, data->helo) != SPF_E_SUCCESS) {
            log("Invalid HELO domain. (%s)\n", data->helo);
            SPF_request_free(spf_request);
            SPF_server_free(spf_server);
            return SENDER_CHECK_ERR;
        }
    }

    if (SPF_request_set_env_from(spf_request, data->envelope_from)) {
        log("Invalid envelope from address. (%s)\n", data->envelope_from);
        SPF_request_free(spf_request);
        SPF_server_free(spf_server);
        return SENDER_CHECK_ERR;
    }

    /* SPF問い合わせ */
    SPF_request_query_mailfrom(spf_request, &spf_response);

    result = SPF_response_result(spf_response);

    DEBUGLOG("result = %s (%d)\n", SPF_strresult(result), result);
    DEBUGLOG("err = %s (%d)\n",
        SPF_strerror(SPF_response_errcode(spf_response)),
        SPF_response_errcode(spf_response));

    SPF_response_free(spf_response);
    SPF_request_free(spf_request);
    SPF_server_free(spf_server);

    /*
     * 結果判定
     * passだのnoneだのneutralだのは、それぞれSPFのRFCで規定されたコード
     */
    switch (result) {
    case SPF_RESULT_PASS:
        // チェック成功
        log(OK_HARM_SPF, data->ip, data->message_id,
            data->envelope_from, data->rcpt_to);
        return SENDER_CHECK_OK;

    case SPF_RESULT_NONE:
        log(NG_HARM_SPFNOTFOUND, data->ip, data->message_id,
            data->envelope_from, data->rcpt_to);
        return SENDER_CHECK_NG;

    case SPF_RESULT_NEUTRAL:
        log(NG_HARM_SPFNEUTRAL,
                data->ip, data->message_id, data->envelope_from, data->rcpt_to);
        return SENDER_CHECK_NG;

    case SPF_RESULT_PERMERROR:
        log(NG_HARM_SPFPERM,
                data->ip, data->message_id, data->envelope_from, data->rcpt_to);
        return SENDER_CHECK_NG;

    case SPF_RESULT_FAIL:
        log(NG_HARM_SPFFAIL,
                data->ip, data->message_id, data->envelope_from, data->rcpt_to);
        return SENDER_CHECK_NG;

    case SPF_RESULT_SOFTFAIL:
        log(NG_HARM_SPFSOFT,
                data->ip, data->message_id, data->envelope_from, data->rcpt_to);
        return SENDER_CHECK_NG;

    case SPF_RESULT_INVALID:
        log(NG_HARM_SPFINV,
                data->ip, data->message_id, data->envelope_from, data->rcpt_to);
        return SENDER_CHECK_NG;

    case SPF_RESULT_TEMPERROR:
        log(ERR_HARM_SPFQUERYFAILURE, data->ip, data->message_id,
            data->envelope_from, data->rcpt_to);
        return SENDER_CHECK_ERR;

    default:
        log("something wrong!:%s:%s:%s:%s\n", data->ip, data->message_id,
            data->envelope_from, data->rcpt_to);
        return SENDER_CHECK_ERR;
    }

    log("something wrong!:%s:%s:%s:%s\n", data->ip, data->message_id,
        data->envelope_from, data->rcpt_to);
    return SENDER_CHECK_ERR;
}
/*
 * args:
 *  data
 *  errmsg
 *
 * ret:
 *  SENDER_CHECK_OK   引いたDNSがメールアドレスのドメイン部分の後方に含まれる
 *  SENDER_CHECK_NG   DNSを引いた結果がなかった
 *  SENDER_CHECK_ERR  
 */
int check_senderip(sender_check_arg_t *data)
{
    /* 初期化 */
    char hostbuf[NI_MAXHOST] = ""; //1025 in netdb.h
    int ret = 0;

    /* DNS逆引き */
    if (data->af == AF_INET) {	/* IPv4 */
        ret = getnameinfo((struct sockaddr *)(&(data->sa.sa_in)),
		sizeof(struct sockaddr_in), hostbuf, sizeof(hostbuf),
		NULL, 0, NI_NAMEREQD);
    } else {			/* IPv6 */
        ret = getnameinfo((struct sockaddr *)(&(data->sa.sa_in6)),
		sizeof(struct sockaddr_in6), hostbuf, sizeof(hostbuf),
		NULL, 0, NI_NAMEREQD);
    }
    if (ret == EAI_NONAME) {
        DEBUGLOG("check_senderip:Error %s\n", gai_strerror(ret));
        log(NG_HARM_NAMENOTFOUND, data->ip, data->message_id, 
		data->envelope_from, data->rcpt_to);
        return SENDER_CHECK_NG;
    }
    if (ret != 0) { 
        DEBUGLOG("check_senderip:Error %s\n", gai_strerror(ret));
        log(ERR_HARM_QUERYFAILURE, data->ip, data->message_id, 
        	data->envelope_from, data->rcpt_to);
        return SENDER_CHECK_ERR;
    }

    /* 送信者メールアドレスのドメイン部と逆引きしたドメイン名を比較 */
    if (comp_domain(data->envelope_from, hostbuf) == SENDER_CHECK_NG) {
        log(NG_HARM_SENDER_IP, data->ip, data->message_id, 
		data->envelope_from, data->rcpt_to);
        return SENDER_CHECK_NG;
    }
    log(OK_HARM_SENDER_IP, data->ip, data->message_id, 
	data->envelope_from, data->rcpt_to);
    return SENDER_CHECK_OK;

}

/*
 * args:
 *  data
 *
 * ret:
 *  SENDER_CHECK_OK   レコードを取得し、名前解決した結果と送信元IPアドレスが一致
 *  SENDER_CHECK_NG   レコードを1件も取得できなかった場合とIPアドレスが一致しなかった場合
 *  SENDER_CHECK_ERR  レコード取得時にエラーが発生した場合
 */
int check_senderdomain(sender_check_arg_t *data)
{
    /* 初期化 */
    char *at;
    int res_comp;

    /* メールアドレスからドメインを取得 */
    at = strchr(data->envelope_from, '@');
    if (at == NULL) {
        log("Invalid Mailaddress.\n");
        return SENDER_CHECK_NG;
    }
    at++;

    /* AもしくはAAAAレコードを引く関数を呼び出す */
    res_comp = comp_ipaddr(at, data);

    /* IPアドレスの形式ごとに返り値判断 */
    if (data->af == AF_INET) {
        switch (res_comp) {
            /* レコードなし以外はログ出力して、そのまま返す */
            case SENDER_CHECK_NG:
                log(NG_HARM_SENDER_DOMAIN_A, data->ip, data->message_id, 
                data->envelope_from, data->rcpt_to);
                break;
            case SENDER_CHECK_ERR:
                log(ERR_HARM_DOMAINQUERYFAILURE_A, data->ip, data->message_id, 
                data->envelope_from, data->rcpt_to);
                return SENDER_CHECK_ERR;
            case SENDER_CHECK_OK:
                log(OK_HARM_SENDER_DOMAIN_A, data->ip, data->message_id, 
                data->envelope_from, data->rcpt_to);
                return SENDER_CHECK_OK;
            /* レコードがなかった場合はMXレコードを引く処理へ */
            case SENDER_CHECK_NO_RECORD:
                log(NO_HARM_SENDER_DOMAIN_A, data->ip, data->message_id, 
                data->envelope_from, data->rcpt_to);
                break;
        }
    } else {
        switch (res_comp) {
            /* レコードなし以外はログ出力して、そのまま返す */
            case SENDER_CHECK_NG:
                log(NG_HARM_SENDER_DOMAIN_AAAA, data->ip, data->message_id, 
                data->envelope_from, data->rcpt_to);
                break;
            case SENDER_CHECK_ERR:
                log(ERR_HARM_DOMAINQUERYFAILURE_AAAA, data->ip, data->message_id, 
                data->envelope_from, data->rcpt_to);
                return SENDER_CHECK_ERR;
            case SENDER_CHECK_OK:
                log(OK_HARM_SENDER_DOMAIN_AAAA, data->ip, data->message_id, 
                data->envelope_from, data->rcpt_to);
                return SENDER_CHECK_OK;
            /* レコードがなかった場合はMXレコードを引く処理へ */
            case SENDER_CHECK_NO_RECORD:
                log(NO_HARM_SENDER_DOMAIN_AAAA, data->ip, data->message_id, 
                data->envelope_from, data->rcpt_to);
                break;
        }
    }

    /* MXレコードを引く関数を呼び出す */
    res_comp = comp_mx(at, data);

    /* 返り値判断 */
    switch (res_comp) {
        case SENDER_CHECK_NG:
            log(NG_HARM_SENDER_DOMAIN_MX, data->ip, data->message_id, 
            data->envelope_from, data->rcpt_to);
            return SENDER_CHECK_NG;
        case SENDER_CHECK_ERR:
            log(ERR_HARM_DOMAINQUERYFAILURE_MX, data->ip, data->message_id, 
            data->envelope_from, data->rcpt_to);
            return SENDER_CHECK_ERR;
        case SENDER_CHECK_OK:
            log(OK_HARM_SENDER_DOMAIN_MX, data->ip, data->message_id, 
            data->envelope_from, data->rcpt_to);
            break;
    }
    return SENDER_CHECK_OK;
}

int
comp_domain(char *sender, char *domain)
{
    char *atp;
    int s_len, d_len;

    /* アットマークの位置を探す */
    atp = strchr(sender, '@');
    if (atp == NULL) {
        return SENDER_CHECK_NG;
    }
    atp++;	/* アットマークの次のポインタを参照 */

    /* 比べる長さを取得 */
    d_len = strlen(domain);
    s_len = strlen(atp);

    /* 送信者ドメインの方が長かったら不一致 */
    if (d_len < s_len) {
        return SENDER_CHECK_NG;
    }

    /* ドメイン名の方が長かったら...  */
    if (d_len > s_len) {
        /* 比べる長さの一つ前が . 以外は不一致 */
        if (*(domain + (d_len - s_len) - 1) != '.') {
            return SENDER_CHECK_NG;
        }
    }

    /* 比較 */
    if (strcasecmp(atp, domain + (d_len - s_len))) {
        return SENDER_CHECK_NG;
    }

    return SENDER_CHECK_OK;
}

/*
 * args:
 *  struct rcptinfo *rdmpasslist  Milterが取得した受信者アドレスリスト
 *  rcptstr                       受信者をカンマ区切りにした文字列
 *
 * ret:
 *  -1            rdmpasslistがNULL
 *  -2            メモリー確保失敗
 *  len_rcptstr   rcptstrの文字数を返す(NULLバイトを含まない)
 */
int concatenate_rcpt(struct rcptinfo *rdmpasslist, char **rcptstr)
{
    int i = NULL;
    char *addr = NULL; //メールアドレス文字列
    char *tmp = NULL;
    size_t sum_len = 0; //recipients文字列の長さ
    size_t addr_len = 0;
    struct rcptinfo *p;

    /* rdmpasslistのNULLチェック */
    if (rdmpasslist == NULL) {
        return -1;
    }

    /* Null 文字分確保 */
    if ((*rcptstr = (char *)malloc(sum_len + 1)) == NULL) {
        return -2;
    }
    //文字列の初期化
    **rcptstr = '\0'; 

    for (p = rdmpasslist; p != NULL; p = p->Next) {
        for (i = 0; (p->rcptlist + i)->rcpt_addr != NULL; i++) {
            addr = (p->rcptlist + i)->rcpt_addr;
            addr_len = (p->rcptlist + i)->rcpt_addr_len;
            sum_len += addr_len;
            tmp = (char *)realloc(*rcptstr, sum_len + 1);
            if (tmp == NULL) {
                free(*rcptstr);
                return -2;
            }
            *rcptstr = tmp;
            //文字列の末尾にアドレスをコピー
            *rcptstr = strcat(*rcptstr, addr);
            if (((p->rcptlist + i + 1)->rcpt_addr != NULL) || (p->Next != NULL)) {
                // 末尾に区切り文字「, 」を挿入
                sum_len += 2;
                tmp = (char *)realloc(*rcptstr, sum_len + 1);
                if (tmp == NULL) {
                    free(*rcptstr);
                    return -2;
                }
                *rcptstr = tmp;
                *rcptstr = strcat(*rcptstr, ", ");
            }
        }
    }
    return sum_len;
}

int check_none(sender_check_arg_t *data)
{
    log(LOG_HARMLESS, data->ip, data->message_id, data->envelope_from, data->rcpt_to);

    return SENDER_CHECK_NONE;
};
