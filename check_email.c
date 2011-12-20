
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <resolv.h>
#include <netdb.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/nameser.h>

#include "check_email.h"

static void socket_flush(int *socket)
{
    char buffer[1024];
    int len = 0;

    do {
        len = read(*socket, buffer, 1023);
    } while (len == 1023);
}


static int send_message(int *socket, char *msg)
{
    int len = 0;
    char buffer[4];
    
    write(*socket, msg, strlen(msg));

    sleep(1);

    if ((len = read(*socket, buffer, 3)) <= 0)
        return 1;

    buffer[3] = '\0';

    socket_flush(socket);

    return atoi(buffer);
}

static int smtp_query(char *server, char *email)
{
    struct hostent *host;
    struct sockaddr_in server_addr;
    int socket_h;

    // init server address
    memset((struct sockaddr_in*)&server_addr, 0, sizeof(server_addr));

    // create a new socket
    if ((socket_h = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        return 1;

    // resolve the host
    if ((host = gethostbyname(server)) == NULL)
        return 2;
    
    // setup family (internet), SMTP port (25) and the address
    server_addr.sin_family      = AF_INET;
    server_addr.sin_port        = htons(25);
    server_addr.sin_addr.s_addr = *((unsigned long*)host->h_addr_list[0]);

    // connect to the server
    if (connect(socket_h, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1)
        return 3;

    // init SMTP connection 
    if (send_message(&socket_h, "HELO check_email\r\n") != 220)
        return 4;

    // tell who wants to send the message, this step is mandatory before RCPT
    // TO but it is not important for us here
    if (send_message(&socket_h, "MAIL FROM:<check_email@invalid.com>\r\n") != 250)
        return 5;

    char buffer[256];
    //snprint append /0 into buffer
    snprintf(buffer, 255, "RCPT TO:<%s>\r\n", email);
    
    // check if the server recognizes this email address as valid
    if (send_message(&socket_h, buffer) != 250)
        return 6;

    // close the smtp connection
    send_message(&socket_h, "QUIT\r\n"); 

    // close the socket
    close(socket_h);

    return 0;
}

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

    // create a list of strings for each of all servers found
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

        // create a string (MAXDNAME is the recommended size for it)
        response[i] = (char*)malloc(MAXDNAME);
        if (response[i] == NULL) {

            // free previous allocated strings. Note I use an inverse logic
            // (message_number to 0) so I need to clean up from the not
            // allocated index + 1 up to the message_number
            int remaining_alloc = i + 1;
            for (remaining_alloc; remaining_alloc < message_number; ++remaining_alloc)
                free(response[remaining_alloc]);

            // free the strings list
            free(response);
            return -5;
        }

        // extract the name of the mail server found into response[i]
        if (ns_name_uncompress(ns_msg_base(ns_handler),
                               ns_msg_end(ns_handler),
                               ns_rr_rdata(ns_record) + NS_INT16SZ,
                               response[i],
                               MAXDNAME) < 0) {
            return -6;
        }
    }
    
    // the caller is now responsible for all this memory allocated
    *server_list = response;

    // return the list of strings size
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
    char *email = "test@gmail.com.br";

    char* pdomain = strchr(email, '@');
    if (!pdomain || !++pdomain)
        return -1;

    if (strlen(pdomain) >= 512)
        return 1;

    int size = dns_mx_lookup(pdomain, &list);

    // negative response = error happened
    if (size < 0)
        return 1;

    // no server found - the mail server for the specified domain is not valid
    if (size == 0 || list == NULL)
        return 0;

    int i;
    for (i = 0; i < size; ++i) {

        printf("%d - %s\n", i, list[i]);

        int ret = smtp_query(list[i], email);

        if (ret == 6) {
            printf("This email is not valid\n");
            break;
        } else if (ret == 0) {
            printf("This is a valid e-mail\n");
            break;
        }
    }

    // free allocated resources
    for (i = 0; i < size; ++i) {

        // item by item...
        free(list[i]);
        
    }
    // ...and finally the list
    free(list);
    list = NULL;

    return 0;
}

