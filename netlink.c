#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include <stdio.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/rtnetlink.h>
#include <memory.h>

void parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
    memset(tb, 0, sizeof(struct rtattr *) * (max + 1));

    while (RTA_OK(rta, len)) {
        if (rta->rta_type <= max) {
            tb[rta->rta_type] = rta;
        }

        rta = RTA_NEXT(rta,len);
    }
}
int rtnl_receive(int fd, struct msghdr *msg, int flags)
{
    int len;

    do { 
        len = recvmsg(fd, msg, flags);
    } while (len < 0 && (errno == EINTR || errno == EAGAIN));

    if (len < 0) {
        perror("Netlink receive failed");
        return -errno;
    }

    if (len == 0) { 
        perror("EOF on netlink");
        return -ENODATA;
    }

    return len;
}

static int rtnl_recvmsg(int fd, struct msghdr *msg, char **answer)
{
    struct iovec *iov = msg->msg_iov;
    char *buf;
    int len;

    iov->iov_base = NULL;
    iov->iov_len = 0;

    len = rtnl_receive(fd, msg, MSG_PEEK | MSG_TRUNC);

    if (len < 0) {
        return len;
    }

    buf = malloc(len);

    if (!buf) {
        perror("malloc failed");
        return -ENOMEM;
    }

    iov->iov_base = buf;
    iov->iov_len = len;

    len = rtnl_receive(fd, msg, 0);

    if (len < 0) {
        free(buf);
        return len;
    }

    *answer = buf;

    return len;
}



static inline int rtm_get_table(struct rtmsg *r, struct rtattr **tb)
{
    __u32 table = r->rtm_table;

    if (tb[RTA_TABLE]) {
        table = *(__u32 *)RTA_DATA(tb[RTA_TABLE]);
    }

    return table;
}

void print_route(struct nlmsghdr* nl_header_answer)
{
    struct rtmsg* r = NLMSG_DATA(nl_header_answer);
    int len = nl_header_answer->nlmsg_len;
    struct rtattr* tb[RTA_MAX+1];
    int table;
    char buf[256];

    len -= NLMSG_LENGTH(sizeof(*r));

    if (len < 0) {
        perror("Wrong message length");
        return;
    }
    
    parse_rtattr(tb, RTA_MAX, RTM_RTA(r), len);

    table = rtm_get_table(r, tb);

    if (r->rtm_family != AF_INET && table != RT_TABLE_MAIN) {
        return;
    }

    if (tb[RTA_DST]) {
        if ((r->rtm_dst_len != 24) && (r->rtm_dst_len != 16)) {
            return;
        }

        printf("%s/%u ", inet_ntop(r->rtm_family, RTA_DATA(tb[RTA_DST]), buf, sizeof(buf)), r->rtm_dst_len);

    } else if (r->rtm_dst_len) {
        printf("0/%u ", r->rtm_dst_len);
    } else {
        printf("default ");
    }

    if (tb[RTA_GATEWAY]) {
        printf("via %s", inet_ntop(r->rtm_family, RTA_DATA(tb[RTA_GATEWAY]), buf, sizeof(buf)));
    }

    if (tb[RTA_OIF]) {
        char if_nam_buf[IF_NAMESIZE];
        int ifidx = *(__u32 *)RTA_DATA(tb[RTA_OIF]);

        printf(" dev %s", if_indextoname(ifidx, if_nam_buf));
    }

    if (tb[RTA_SRC]) {
        printf("src %s", inet_ntop(r->rtm_family, RTA_DATA(tb[RTA_SRC]), buf, sizeof(buf)));
    }

    printf("\n");
}
/* Helper structure for ip address data and attributes */
typedef struct {
    char family;
    char bitlen;
    unsigned char data[sizeof(struct in6_addr)];
} _inet_addr;

#define NLMSG_TAIL(nmsg) \
    ((struct rtattr *) (((void *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

/* Add new data to rtattr */
int rtattr_add(struct nlmsghdr *n, int maxlen, int type, const void *data, int alen)
{
    int len = RTA_LENGTH(alen);
    struct rtattr *rta;

    if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > maxlen) {
        fprintf(stderr, "rtattr_add error: message exceeded bound of %d\n", maxlen);
        return -1;
    }

    rta = NLMSG_TAIL(n);
    rta->rta_type = type;
    rta->rta_len = len; 

    if (alen) {
        memcpy(RTA_DATA(rta), data, alen);
    }

    n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);

    return 0;
}

int do_route(int sock, int cmd, int flags, _inet_addr *dst, _inet_addr *gw, int def_gw, int if_idx)
{
    struct {
        struct nlmsghdr n;
        struct rtmsg r;
        char buf[4096];
    } nl_request;

    /* Initialize request structure */
    nl_request.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    nl_request.n.nlmsg_flags = NLM_F_REQUEST | flags;
    nl_request.n.nlmsg_type = cmd;
    nl_request.r.rtm_family = dst->family;
    nl_request.r.rtm_table = RT_TABLE_MAIN;
    nl_request.r.rtm_scope = RT_SCOPE_NOWHERE;

    /* Set additional flags if NOT deleting route */
    if (cmd != RTM_DELROUTE) {
        nl_request.r.rtm_protocol = RTPROT_BOOT;
        nl_request.r.rtm_type = RTN_UNICAST;
    }

    nl_request.r.rtm_family = dst->family;
    nl_request.r.rtm_dst_len = dst->bitlen;


    if (nl_request.r.rtm_family == AF_INET6) {
        nl_request.r.rtm_scope = RT_SCOPE_UNIVERSE;
    } else {
        nl_request.r.rtm_scope = RT_SCOPE_LINK;
    }


    if (gw->bitlen != 0) {
        rtattr_add(&nl_request.n, sizeof(nl_request), RTA_GATEWAY, &gw->data, gw->bitlen / 8);
        nl_request.r.rtm_scope = 0;
        nl_request.r.rtm_family = gw->family;
    }

    if (!def_gw) {
    
        rtattr_add(&nl_request.n, sizeof(nl_request), RTA_DST, &dst->data, dst->bitlen / 8);


        rtattr_add(&nl_request.n, sizeof(nl_request), RTA_OIF, &if_idx, sizeof(int));
    }

    /* Send message to the netlink */
    return send(sock, &nl_request, sizeof(nl_request), 0);
}

/* Simple parser of the string IP address */
int read_addr(char *addr, _inet_addr *res)
{
    if (strchr(addr, ':')) {
        res->family = AF_INET6;
        res->bitlen = 128;
    } else {
        res->family = AF_INET;
        res->bitlen = 32;
    }

    return inet_pton(res->family, addr, res->data);
}
int open_netlink()
{
    struct sockaddr_nl saddr;

    int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

    if (sock < 0) {
        perror("Failed to open netlink socket");
        return -1;
    }

    memset(&saddr, 0, sizeof(saddr));

    saddr.nl_family = AF_NETLINK;
    saddr.nl_pid = getpid();

    if (bind(sock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
        perror("Failed to bind to netlink socket");
        close(sock);
        return -1;
    }

    return sock;
}
int do_route_dump_requst(int sock)
{
    struct {
        struct nlmsghdr nlh;
        struct rtmsg rtm;
    } nl_request;

    nl_request.nlh.nlmsg_type = RTM_GETROUTE;
    nl_request.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nl_request.nlh.nlmsg_len = sizeof(nl_request);
    nl_request.nlh.nlmsg_seq = time(NULL);
    nl_request.rtm.rtm_family = AF_INET;

    return send(sock, &nl_request, sizeof(nl_request), 0);
}

int get_route_dump_response(int sock)
{
    struct sockaddr_nl nladdr;
    struct iovec iov;
    struct msghdr msg = {
        .msg_name = &nladdr,
        .msg_namelen = sizeof(nladdr),
        .msg_iov = &iov,
        .msg_iovlen = 1,
    };

    char *buf;
    int dump_intr = 0;
    /* Get the message */
    int status = rtnl_recvmsg(sock, &msg, &buf);
    /* Pointer to the messages head */
    struct nlmsghdr *h = (struct nlmsghdr *)buf;
    int msglen = status;

    printf("Main routing table IPv4\n");
    /* Iterate through all messages in buffer */
    while (NLMSG_OK(h, msglen)) {
        if (h->nlmsg_flags & NLM_F_DUMP_INTR) {
            fprintf(stderr, "Dump was interrupted\n");
            free(buf);
            return -1;
        }

        if (nladdr.nl_pid != 0) {
            continue;
        }

        if (h->nlmsg_type == NLMSG_ERROR) {
            perror("netlink reported error");
            free(buf);
        }

        print_route(h);

        h = NLMSG_NEXT(h, msglen);
    }

    free(buf);

    return status;
}


#define NEXT_CMD_ARG() do { argv++; if (--argc <= 0) exit(-1); } while(0)
int main(int argc, char **argv)
{
    switch(argc)
    {
    case 1: 
    {
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);   

    if (fd < 0) {
	printf("Failed to create netlink socket: %s\n", (char*)strerror(errno));
	return -1;
    }

    struct sockaddr_nl  nladdr;  
    char buf[8192];            
    struct iovec iov;          
    iov.iov_base = buf;         
    iov.iov_len = sizeof(buf); 

    memset(&nladdr, 0, sizeof(nladdr));

    nladdr.nl_family = AF_NETLINK;      
    nladdr.nl_groups =   RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE;  
    nladdr.nl_pid = getpid();    
    if (bind(fd, (struct sockaddr*)&nladdr, sizeof(nladdr)) < 0) 
    {     
    printf("Failed to bind netlink socket: %s\n", (char*)strerror(errno));
    close(fd);
    return 1;
    }   
    /* initialize protocol message*/
    struct msghdr msg;  
    {
	msg.msg_name = &nladdr;                  
	msg.msg_namelen = sizeof(nladdr);       
	msg.msg_iov = &iov;                   
	msg.msg_iovlen = 1;                    
    }   
    while (1) {
	ssize_t status = recvmsg(fd, &msg, MSG_DONTWAIT);
	
	if (status < 0) {
	    if (errno == EINTR || errno == EAGAIN)
	    {
		usleep(250000);
		continue;
	    }
	    printf("Failed to read netlink: %s", (char*)strerror(errno));
	    continue;
	}

	if (msg.msg_namelen != sizeof(nladdr)) { 
	    printf("Invalid length of the sender address struct\n");
	    continue;
	}

	/*message parser*/
	struct nlmsghdr *h;

	for (h = (struct nlmsghdr*)buf; status >= (ssize_t)sizeof(*h); ) {   /* read all messagess headers*/
	    int len = h->nlmsg_len;
	    int l = len - sizeof(*h);
	    char *ifName;

	    if ((l < 0) || (len > status)) {
		printf("Invalid message length: %i\n", len);
		continue;
	    }

	    /*check message type*/
	    if ((h->nlmsg_type == RTM_NEWROUTE) || (h->nlmsg_type == RTM_DELROUTE)) 
	    { 
		printf("Routing table was changed\n");  
	    } 
	    else 
	    {   
		char *ifUpp;
		char *ifRunn;
		struct ifinfomsg *ifi;  
		struct rtattr *tb[IFLA_MAX + 1];

		ifi = (struct ifinfomsg*) NLMSG_DATA(h);    /* get information about changed network interface*/

		parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifi), h->nlmsg_len);  /* get attributes*/
		
		if (tb[IFLA_IFNAME]) {  
		    ifName = (char*)RTA_DATA(tb[IFLA_IFNAME]); /* get network interface name */
		}

		if (ifi->ifi_flags & IFF_UP) { /* get UP flag of the network interface*/
		    ifUpp = (char*)"UP";
		} else {
		    ifUpp = (char*)"DOWN";
		}

		if (ifi->ifi_flags & IFF_RUNNING) { /* get UNNING flag of the network interface*/
		    ifRunn = (char*)"RUNNING";
		} else {
		    ifRunn = (char*)"NOT RUNNING";
		}

		char ifAddress[256];    /* network addr*/
		struct ifaddrmsg *ifa; /* structure for network interface data*/
		struct rtattr *tba[IFA_MAX+1];

		ifa = (struct ifaddrmsg*)NLMSG_DATA(h); /* get data from the network interface*/

		parse_rtattr(tba, IFA_MAX, IFA_RTA(ifa), h->nlmsg_len);

		if (tba[IFA_LOCAL]) {
		    inet_ntop(AF_INET, RTA_DATA(tba[IFA_LOCAL]), ifAddress, sizeof(ifAddress)); /* get IP addr*/
		}

		switch (h->nlmsg_type) { 
		    case RTM_DELADDR:
		        printf("Interface %s: address was removed\n", ifName);
		        break;

		    case RTM_DELLINK:
		        printf("Network interface %s was removed\n", ifName);
		        break;

		    case RTM_NEWLINK:
		        printf("New network interface %s, state: %s %s\n", ifName, ifUpp, ifRunn);
		        break;

		    case RTM_NEWADDR:
		        printf("Interface %s: new address was assigned: %s\n", ifName, ifAddress);
		        break;
		}
	    }

	    status -= NLMSG_ALIGN(len); 

	    h = (struct nlmsghdr*)((char*)h + NLMSG_ALIGN(len));    /* get next message*/
		}
		usleep(250000); 
	    }

	  close(fd);  
	}
	case 3:
	{	    
            int nl_sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
            if (nl_sock < 0) 
            {
                perror("Failed to open netlink socket");
                return -1;
            }
            struct sockaddr_nl nladdr;
    	    memset(&nladdr, 0, sizeof(nladdr));
	    if (do_route_dump_requst(nl_sock) < 0) {
		perror("Failed to perfom request");
		close(nl_sock);
		return -1;
	    }
	    get_route_dump_response(nl_sock);
	    close (nl_sock);
	}
	case 6:
        {
	    int default_gw = 0;
	    int if_idx = 0;
	    int nl_sock;
	    _inet_addr to_addr = { 0 };
	    _inet_addr gw_addr = { 0 };

	    int nl_cmd;
	    int nl_flags;

	    /* Parse command line arguments */
	    while (argc > 0) {
		if (strcmp(*argv, "add") == 0) {
		    nl_cmd = RTM_NEWROUTE;
		    nl_flags = NLM_F_CREATE | NLM_F_EXCL;

		} else if (strcmp(*argv, "del") == 0) {
		    nl_cmd = RTM_DELROUTE;
		    nl_flags = 0;

		} else if (strcmp(*argv, "to") == 0) {
		    NEXT_CMD_ARG(); 

		    if (read_addr(*argv, &to_addr) != 1) {
			fprintf(stderr, "Failed to parse destination network %s\n", *argv);
			exit(-1);
		    }

		} else if (strcmp(*argv, "dev") == 0) {
		    NEXT_CMD_ARG(); 

		    if_idx = if_nametoindex(*argv);

		} else if (strcmp(*argv, "via") == 0) {
		    NEXT_CMD_ARG(); 
		 
		    if (strcmp(*argv, "default") == 0) {
			default_gw = 1;
			NEXT_CMD_ARG();
		    }

		    if (read_addr(*argv, &gw_addr) != 1) {
			fprintf(stderr, "Failed to parse gateway address %s\n", *argv);
			exit(-1);
		    }
		}

		argc--; argv++;
	    }		  
	    struct sockaddr_nl saddr;
	    int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	    if (sock < 0) {
		perror("Failed to open netlink socket");
		return -1;
	    }
	    memset(&saddr, 0, sizeof(saddr));
	    do_route(sock, nl_cmd, nl_flags, &to_addr, &gw_addr, default_gw, if_idx);
	    close (nl_sock);
	    }
	}
	return 0;	    	
}
