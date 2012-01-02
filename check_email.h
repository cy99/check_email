#ifndef CHECKEMAIL_H_
#define CHECKEMAIL_H_

enum rcode {

    SUCCESS                  = 0,
    
    SOCKET_READ_ERROR        = -1,
    SOCKET_CREATE_ERROR      = -2,
    SOCKET_HOSTBYNAME_ERROR  = -3,
    SOCKET_CONNECT_ERROR     = -4,

    SMTP_HELO_ERROR          = -5,
    SMTP_MAILFROM_ERROR      = -6,
    SMTP_INVALID_EMAIL_ADDR  = -7,

    DNS_RESQUERY_ERROR       = -8,
    DNS_INITPARSER_ERROR     = -9,
    DNS_MSGCOUNT_ERROR       = -10,
    DNS_UNCOMPRESS_ERROR     = -11,

    INPUT_INVALID            = -12,
    INPUT_INVALID_EMAIL      = -13,
    INPUT_INVALID_DOMAIN     = -14,

    OUT_OF_BOUND             = -15,
    OUT_OF_MEMORY            = -16
};

int dns_mx_lookup(char *domain, char ***server_list);
int smtp_query(char *server, char *email);

#endif
