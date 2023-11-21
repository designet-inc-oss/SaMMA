/*
 * samma
 * sender_check.h
 *
 * To do SPF check or Sender-IP check or something
 */
#ifndef _SENDER_CHECK_H
#define _SENDER_CHECK_H

#include <netinet/in.h>

/**
 * error messages
 */
#define SC_ERR_MEM "Cannot allocate memory: %s"
#define SC_ERR_INVALID "Invalid item is set: %s"


/**
 * type def
 */
#define SENDER_CHECK_OK		1
#define SENDER_CHECK_NG		0
#define SENDER_CHECK_NONE	3
#define SENDER_CHECK_ERR	-1
#define SENDER_CHECK_NO_RECORD	2
#define EDNS0_MAXPACKET 4096

//log format
#define ERR_HARM_QUERYFAILURE   "Failed to query DNS.: source=%s, message-id=%s, sender=%s, recipients=%s\n"
#define ERR_HARM_SPFQUERYFAILURE   "Failed to query SPF record.: source=%s, message-id=%s, sender=%s, recipients=%s\n"
#define ERR_HARM_DOMAINQUERYFAILURE_A  "Failed to query A record.: source=%s, message-id=<%s>, sender=%s, recipients=%s\n"
#define ERR_HARM_DOMAINQUERYFAILURE_MX "Failed to query MX record.: source=%s, message-id=<%s>, sender=%s, recipients=%s\n"
#define ERR_HARM_DOMAINQUERYFAILURE_AAAA  "Failed to query AAAA record.: source=%s, message-id=<%s>, sender=%s, recipients=%s"

#define NG_HARM_SPFNEUTRAL   "SPF NG (neutral).: source=%s, message-id=%s, sender=%s, recipients=%s\n"
#define NG_HARM_SPFPERM   "SPF NG (permerror).: source=%s, message-id=%s, sender=%s, recipients=%s\n"
#define NG_HARM_SPFFAIL   "SPF NG (fail).: source=%s, message-id=%s, sender=%s, recipients=%s\n"
#define NG_HARM_SPFSOFT   "SPF NG (softfail).: source=%s, message-id=%s, sender=%s, recipients=%s\n"
#define NG_HARM_SPFINV   "SPF NG (invalid).: source=%s, message-id=%s, sender=%s, recipients=%s\n"
#define NG_HARM_NAMENOTFOUND   "No PTR record in DNS.: source=%s, message-id=%s, sender=%s, recipients=%s\n"
#define OK_HARM_SENDER_IP       "Sender IPaddress OK.: source=%s, message-id=%s, sender=%s, recipients=%s\n"
#define NG_HARM_SENDER_IP       "Sender NG.: source=%s, message-id=%s, sender=%s, recipients=%s\n"

#define NG_HARM_SPFNOTFOUND   "No SPF record in DNS.: source=%s, message-id=%s, sender=%s, recipients=%s\n"
#define OK_HARM_SPF       "SPF OK.: source=%s, message-id=<%s>, sender=%s, recipients=%s\n"

#define OK_HARM_SENDER_DOMAIN_A   "A record check OK.: source=%s, message-id=<%s>, sender=%s, recipients=%s\n"
#define OK_HARM_SENDER_DOMAIN_MX  "MX record check OK.: source=%s, message-id=<%s>, sender=%s, recipients=%s\n"
#define NO_HARM_SENDER_DOMAIN_A   "No A record in DNS.: source=%s, message-id=%s, sender=%s, recipients=%s\n"
#define NO_HARM_SENDER_DOMAIN_MX  "No MX record in DNS.: source=%s, message-id=%s, sender=%s, recipients=%s\n"
#define NG_HARM_SENDER_DOMAIN_A   "A record check NG.: source=%s, message-id=<%s>, sender=%s, recipients=%s\n"
#define NG_HARM_SENDER_DOMAIN_MX  "MX record check NG.: source=%s, message-id=<%s>, sender=%s, recipients=%s\n"
#define OK_HARM_SENDER_DOMAIN_AAAA   "AAAA record check OK.: source=%s, message-id=<%s>, sender=%s, recipients=%s\n"
#define NO_HARM_SENDER_DOMAIN_AAAA   "No AAAA record in DNS.: source=%s, message-id=%s, sender=%s, recipients=%s\n"
#define NG_HARM_SENDER_DOMAIN_AAAA   "AAAA record check NG.: source=%s, message-id=<%s>, sender=%s, recipients=%s\n"

#define NG_HARMLESS       "harmless: source=%s, message-id=%s, sender=%s, recipients=%s\n"

/* "check function" argument struct */
typedef struct sender_check_arg {
    char *ip;
    char *helo;
    char *envelope_from;
    char *message_id;
    char *rcpt_to;		/* for log message */
    int  af;			/* AF_INET or AF_INET6 */
    union saddr {
        struct sockaddr_in  sa_in;
        struct sockaddr_in6 sa_in6;
    } sa;
} sender_check_arg_t;

typedef struct sender_check_functions {
    int (*function)(sender_check_arg_t *data);
    struct sender_check_functions *next;
} sender_check_functions_t;


/**
 * functions
 */

/**
 * to set functions to struct config
 * argument:
 *    char *setting : 'SenderCheck' string in samma.conf
 * returns:
 *    char *: errormessage or NULL
 */
char *set_sender_checker(char *setting, void **pointer);
void free_sender_checker(sender_check_functions_t *list);

/* check function */
int check_sender();


#endif		/* _SENDER_CHECK_H */
