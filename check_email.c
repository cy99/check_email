
#include <stdio.h>
#include <stdlib.h>

#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include "check_email.h"

static int dns_mx_lookup(char *domain, char ***server_list)
{
    int answer_len, message_number;
    unsigned char answer[NS_PACKETSZ];
    char **response;

    ns_rr ns_record;
    ns_msg ns_handler;

    // lookup the DNS MX records - responsible for accepting email messages    
    if ((answer_len = res_query(domain, C_IN, T_MX, answer, NS_PACKETSZ)) < 0)
        return -1;

    // initparser is the first function to be called when using the name server
    // library routines. It fills in the ns_handler data structure
    if (ns_initparse(answer, answer_len, &ns_handler) < 0)
        return -2;

    // get the counter from the header section of the response message
    if ((message_number = ns_msg_count(ns_handler, ns_s_an)) < 0)
        return -3;

    response = (char**)malloc(sizeof(char*) * message_number);
    if (response == NULL)
        return -4;

    int i;
    for (i = message_number; i >= 0; --i) {
    
        // extract the data from the response record and add into the ns_record
        if (ns_parserr(&ns_handler, ns_s_an, i, &ns_record))
            continue;

        // record class must be ns_c_in (C_IN - internet) AND must be of MX
        // record type
        if (ns_rr_class(ns_record) != ns_c_in || ns_rr_type(ns_record) != ns_t_mx)
            continue;

        response[i] = (char*)malloc(MAXDNAME);
        if (response[i] == NULL) {
            free(response);
            return -5;
        }

        if (ns_name_uncompress(ns_msg_base(ns_handler),
                               ns_msg_end(ns_handler),
                               ns_rr_rdata(ns_record) + NS_INT16SZ,
                               response[i],
                               MAXDNAME) < 0) {
            return -6;
        }
    }
    
    *server_list = response;

    return message_number;
}

/*
http://docstore.mik.ua/orelly/networking_2ndEd/dns/ch15_02.htm
http://stackoverflow.com/questions/1688432/querying-mx-record-in-c-linux/1689539#1689539
http://www.linuxforums.org/articles/e-mail-architecture-part-ii_278.html

gcc -g check_email.c -lresolv -o check

valgrind -v --leak-check=full ./check
*/
int main()
{
    char **list = NULL;
    int size = dns_mx_lookup("gmail.com", &list);

    if (size < 0)
        return 1;

    if (size == 0 || list == NULL)
        return 0;

    int i;
    for (i = 0; i < size; ++i) {

        printf("%d - %s\n", i, list[i]);

    }

    for (i = 0; i < size; ++i) {

        free(list[i]);
        
    }
    free(list);
    list = NULL;


    return 0;
}

