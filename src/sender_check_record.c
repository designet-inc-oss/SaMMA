#include "log.h"
#include "sender_check_record.h"

/**
 * args:
 *  domain    : 送信元メールアドレスから取得したドメイン
 *  from_addr : data構造体に含まれているin_addr構造体
 * ret:
 *  SENDER_CHECK_OK        : Aレコードを取得し、送信元IPアドレスが一致した場合
 *  SENDER_CHECK_NG        : AレコードとIPアドレスが一致しなかった場合
 *  SENDER_CHECK_ERR       : レコード取得時にエラーが発生した場合
 *  SENDER_CHECK_NO_RECORD : Aレコードを1件も引けなかった場合
 */
int comp_ipaddr_ipv4(char *domain, struct in_addr *from_addr)
{
    int len, an_num, chk_addr, loop_num;
    u_char nsbuf[EDNS0_MAXPACKET];
    ns_msg msg;
    ns_rr rr;

    DEBUGLOG("comp_ipaddr_ipv4():domain=[%s]", domain);

    /* Query A record */
    len = res_query(domain, ns_c_any, ns_t_a, nsbuf, sizeof(nsbuf));
    if (len < 0) {
        if (errno == 0) {
            DEBUGLOG("comp_ipaddr_ipv4(): No A record");
            return SENDER_CHECK_NO_RECORD;
        }
        DEBUGLOG("comp_ipaddr_ipv4(): DNS error: %s(%d)", strerror(errno), errno);
        return SENDER_CHECK_ERR;
    }

    /* Parse result */
    ns_initparse(nsbuf, len, &msg);
    
    /* Get number of answer section */
    an_num = ns_msg_count(msg, ns_s_an);
    DEBUGLOG("comp_ipaddr_ipv4(): an_num=[%d]\n", an_num);
    
    /* Compare A record and source ip address */
    for (loop_num = 0; loop_num < an_num; loop_num++) {
        ns_parserr(&msg, ns_s_an, loop_num, &rr);
        chk_addr = memcmp(from_addr, rr.rdata, sizeof(struct in_addr));
        if (chk_addr == 0) {
            DEBUGLOG("comp_ipaddr_ipv4(): OK");
            return SENDER_CHECK_OK;
        }
    }

    DEBUGLOG("comp_ipaddr_ipv4(): No match");
    return SENDER_CHECK_NG;
}

/**
 * args:
 *  domain    : 送信元メールアドレスから取得したドメイン
 *  from_addr : data構造体に含まれているin6_addr構造体
 * ret:
 *  SENDER_CHECK_OK        : AAAAレコードを取得し、送信元IPアドレスが一致した場合
 *  SENDER_CHECK_NG        : AAAAレコードとIPアドレスが一致しなかった場合
 *  SENDER_CHECK_ERR       : レコード取得時にエラーが発生した場合
 *  SENDER_CHECK_NO_RECORD : AAAAレコードを1件も引けなかった場合
 */
int comp_ipaddr_ipv6(char *domain, struct in6_addr *from_addr)
{
    int len, an_num, chk_addr, loop_num;
    u_char nsbuf[EDNS0_MAXPACKET];
    ns_msg msg;
    ns_rr rr;

    /* Query AAAA record */
    len = res_query(domain, ns_c_any, ns_t_aaaa, nsbuf, sizeof(nsbuf));
    if (len < 0) {
        if (errno == 0) {
            DEBUGLOG("comp_ipaddr_ipv6(): No AAAA record");
            return SENDER_CHECK_NO_RECORD;
        }
        DEBUGLOG("comp_ipaddr_ipv6(): DNS error: %s(%d)", strerror(errno), errno);
        return SENDER_CHECK_ERR;
    }

    /* Parse result */
    ns_initparse(nsbuf, len, &msg);
    
    /* Get number of answer section */
    an_num = ns_msg_count(msg, ns_s_an);
    DEBUGLOG("comp_ipaddr_ipv6(): an_num=[%d]\n", an_num);
    
    /* Compare AAAA record and source ip address */
    for (loop_num = 0; loop_num < an_num; loop_num++) {
        ns_parserr(&msg, ns_s_an, loop_num, &rr);
        chk_addr = memcmp(from_addr, rr.rdata, sizeof(struct in6_addr));
        if (chk_addr == 0) {
            DEBUGLOG("comp_ipaddr_ipv6(): OK");
            return SENDER_CHECK_OK;
        }
    }

    DEBUGLOG("comp_ipaddr_ipv6(): No match");
    return SENDER_CHECK_NG;
}


/**
 * args:
 *  domain : 送信元メールアドレスから取得したドメイン
 *  data   : data構造体
 * ret:
 *  SENDER_CHECK_OK        : レコードを取得し、送信元IPアドレスが一致した場合
 *  SENDER_CHECK_NG        : レコードとIPアドレスが一致しなかった場合
 *  SENDER_CHECK_ERR       : レコード取得時にエラーが発生した場合
 *  SENDER_CHECK_NO_RECORD : レコードを1件も引けなかった場合
 */
int comp_ipaddr(char *domain, sender_check_arg_t *data)
{
    int res_comp;

    /* 渡されたdata構造体のafを元にAを引くかAAAAを引くか判断 */
    if (data->af == AF_INET) {
        res_comp = comp_ipaddr_ipv4(domain, &(data->sa).sa_in.sin_addr);
    } else {
        res_comp = comp_ipaddr_ipv6(domain, &(data->sa).sa_in6.sin6_addr);
    }
    return res_comp;
}

/**
 * args:
 *  domain : 送信元メールアドレスから取得したドメイン
 *  data   : data構造体
 * ret:
 *  SENDER_CHECK_OK        : Aレコードを取得し、送信元IPアドレスが一致した場合
 *  SENDER_CHECK_NG        : AレコードとIPアドレスが一致しなかった場合
 *  SENDER_CHECK_ERR       : レコード取得時にエラーが発生した場合
 *  SENDER_CHECK_NO_RECORD : Aレコードを1件も引けなかった場合
 */
int comp_mx(char *domain, sender_check_arg_t *data)
{
    int len, len_dom, an_num, qd_num, loop_num, res_mx;
    u_char nsbuf[EDNS0_MAXPACKET];
    u_char *conts;
    ns_msg msg;
    char dom[NS_MAXDNAME];

    /* Query mx record */
    len = res_query(domain, ns_c_any, ns_t_mx, nsbuf, sizeof(nsbuf));
    if (len < 0) {
        if (errno == 0) {
            DEBUGLOG("comp_mx(): No mx record");
            return SENDER_CHECK_NG;
        }
        DEBUGLOG("comp_mx(): DNS error: %s(%d)", strerror(errno), errno);
        return SENDER_CHECK_ERR;
    }

    /* Parse result */
    ns_initparse(nsbuf, len, &msg);

    /* Get number of question section */
    qd_num = ns_msg_count(msg, ns_s_qd);
    DEBUGLOG("comp_mx(): qd_num=[%d]", qd_num);

    /* Get number of answer section */
    an_num = ns_msg_count(msg, ns_s_an);
    DEBUGLOG("comp_mx(): an_num=[%d]", an_num);

    /* Skip header */
    conts = nsbuf + sizeof(HEADER);

    /*
     * Parse Query section
     */
    for (loop_num = 0; loop_num < qd_num; loop_num++) {
        /* Get domain name */
        len_dom = dn_expand(nsbuf, nsbuf + len, conts, dom, sizeof(dom));
        if (len_dom < 0) {
            DEBUGLOG("comp_mx(): dn_expand() error 0");
            return SENDER_CHECK_ERR;
        }
        DEBUGLOG("comp_mx(1): len_dom=[%d],dom=[%s]", len_dom, dom);

        /* Skip Name */
        conts += len_dom;

        /* Skip Type(2bytes),Class(2bytes) */
        conts += NS_INT16SZ * 2;
    }
    
    /*
     * Parse Answer section
     */
    for (loop_num = 0; loop_num < an_num; loop_num++) {
        /* Get domain name */
        len_dom = dn_expand(nsbuf, nsbuf + len, conts, dom, sizeof(dom));
        if (len_dom < 0) {
            DEBUGLOG("comp_mx(): dn_expand() error 1");
            return SENDER_CHECK_ERR;
        }
        DEBUGLOG("comp_mx(2): len_dom=[%d],dom=[%s]", len_dom, dom);

        /* Skip Name */
        conts += len_dom;

        /*
         * Skip Type(2bytes),Class(2bytes),TTL(4bytes),
         *      Length(2bytes),Preference(2bytes)
         */
        conts += NS_INT16SZ * 4 + NS_INT32SZ;

        /* Get MX record */
        len_dom = dn_expand(nsbuf, nsbuf + len, conts, dom, sizeof(dom));
        if (len_dom < 0) {
            DEBUGLOG("comp_mx(): dn_expand() error 2");
            return SENDER_CHECK_ERR;
        }
        DEBUGLOG("comp_mx(3): len_dom=[%d],dom=[%s]", len_dom, dom);

        /* Skip MX */
        conts += len_dom;

        /* Compare mx record and source ip address */
        res_mx = comp_ipaddr(dom, data);
        switch (res_mx) {
            case SENDER_CHECK_ERR:
            case SENDER_CHECK_OK:
                return res_mx;
        }
    }
    return SENDER_CHECK_NG;
}
