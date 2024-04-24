/*-----------------------------------------------------------------------------
 * file:  sr_rt.c
 * date:  Mon Oct 07 04:02:12 PDT 2002
 * Author:  casado@stanford.edu
 *
 * Description:
 *
 *---------------------------------------------------------------------------*/

#include "sr_protocol.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>


#include <sys/socket.h>
#include <netinet/in.h>
#define __USE_MISC 1 /* force linux to show inet_aton */
#include <arpa/inet.h>

#include "sr_rt.h"
#include "sr_if.h"
#include "sr_utils.h"
#include "sr_router.h"

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/

int sr_load_rt(struct sr_instance* sr,const char* filename)
{
    FILE* fp;
    char  line[BUFSIZ];
    char  dest[32];
    char  gw[32];
    char  mask[32];    
    char  iface[32];
    struct in_addr dest_addr;
    struct in_addr gw_addr;
    struct in_addr mask_addr;
    int clear_routing_table = 0;

    /* -- REQUIRES -- */
    assert(filename);
    if( access(filename,R_OK) != 0)
    {
        perror("access");
        return -1;
    }

    fp = fopen(filename,"r");

    while( fgets(line,BUFSIZ,fp) != 0)
    {
        sscanf(line,"%s %s %s %s",dest,gw,mask,iface);
        if(inet_aton(dest,&dest_addr) == 0)
        { 
            fprintf(stderr,
                    "Error loading routing table, cannot convert %s to valid IP\n",
                    dest);
            return -1; 
        }
        if(inet_aton(gw,&gw_addr) == 0)
        { 
            fprintf(stderr,
                    "Error loading routing table, cannot convert %s to valid IP\n",
                    gw);
            return -1; 
        }
        if(inet_aton(mask,&mask_addr) == 0)
        { 
            fprintf(stderr,
                    "Error loading routing table, cannot convert %s to valid IP\n",
                    mask);
            return -1; 
        }
        if( clear_routing_table == 0 ){
            printf("Loading routing table from server, clear local routing table.\n");
            sr->routing_table = 0;
            clear_routing_table = 1;
        }
        sr_add_rt_entry(sr,dest_addr,gw_addr,mask_addr,(uint32_t)0,iface);
    } /* -- while -- */

    return 0; /* -- success -- */
} /* -- sr_load_rt -- */

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/
int sr_build_rt(struct sr_instance* sr){
    struct sr_if* interface = sr->if_list;
    char  iface[32];
    struct in_addr dest_addr;
    struct in_addr gw_addr;
    struct in_addr mask_addr;

    while (interface){
        dest_addr.s_addr = (interface->ip & interface->mask);
        gw_addr.s_addr = 0;
        mask_addr.s_addr = interface->mask;
        strcpy(iface, interface->name);
        sr_add_rt_entry(sr, dest_addr, gw_addr, mask_addr, (uint32_t)0, iface);
        interface = interface->next;
    }
    return 0;
}

void sr_add_rt_entry(struct sr_instance* sr, struct in_addr dest,
struct in_addr gw, struct in_addr mask, uint32_t metric, char* if_name)
{   
    struct sr_rt* rt_walker = 0;

    /* -- REQUIRES -- */
    assert(if_name);
    assert(sr);

    pthread_mutex_lock(&(sr->rt_lock));
    /* -- empty list special case -- */
    if(sr->routing_table == 0)
    {
        sr->routing_table = (struct sr_rt*)malloc(sizeof(struct sr_rt));
        assert(sr->routing_table);
        sr->routing_table->next = 0;
        sr->routing_table->dest = dest;
        sr->routing_table->gw   = gw;
        sr->routing_table->mask = mask;
        strncpy(sr->routing_table->interface,if_name,sr_IFACE_NAMELEN);
        sr->routing_table->metric = metric;
        time_t now;
        time(&now);
        sr->routing_table->updated_time = now;

        pthread_mutex_unlock(&(sr->rt_lock));
        return;
    }

    /* -- find the end of the list -- */
    rt_walker = sr->routing_table;
    while(rt_walker->next){
      rt_walker = rt_walker->next; 
    }

    rt_walker->next = (struct sr_rt*)malloc(sizeof(struct sr_rt));
    assert(rt_walker->next);
    rt_walker = rt_walker->next;

    rt_walker->next = 0;
    rt_walker->dest = dest;
    rt_walker->gw   = gw;
    rt_walker->mask = mask;
    strncpy(rt_walker->interface,if_name,sr_IFACE_NAMELEN);
    rt_walker->metric = metric;
    time_t now;
    time(&now);
    rt_walker->updated_time = now;
    
     pthread_mutex_unlock(&(sr->rt_lock));
} /* -- sr_add_entry -- */

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/

void sr_print_routing_table(struct sr_instance* sr)
{
    pthread_mutex_lock(&(sr->rt_lock));
    struct sr_rt* rt_walker = 0;

    if(sr->routing_table == 0)
    {
        printf(" *warning* Routing table empty \n");
        pthread_mutex_unlock(&(sr->rt_lock));
        return;
    }
    printf("  <---------- Router Table ---------->\n");
    printf("Destination\tGateway\t\tMask\t\tIface\tMetric\tUpdate_Time\n");

    rt_walker = sr->routing_table;
    
    while(rt_walker){
        if (rt_walker->metric < INFINITY)
            sr_print_routing_entry(rt_walker);
        rt_walker = rt_walker->next;
    }
    pthread_mutex_unlock(&(sr->rt_lock));


} /* -- sr_print_routing_table -- */

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/

void sr_print_routing_entry(struct sr_rt* entry)
{
    /* -- REQUIRES --*/
    assert(entry);
    assert(entry->interface);
    
    char buff[20];
    struct tm* timenow = localtime(&(entry->updated_time));
    strftime(buff, sizeof(buff), "%H:%M:%S", timenow);
    printf("destination: %s\n",inet_ntoa(entry->dest));
    printf("gateway: %s\n",inet_ntoa(entry->gw));
    printf("subnet mask: %s\n",inet_ntoa(entry->mask));
    printf("interface: %s\n",entry->interface);
    printf("metric: %d\n",entry->metric);
    printf("buffer: %s\n", buff);

} /* -- sr_print_routing_entry -- */


void *sr_rip_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    while (1) {
        sleep(5);
        pthread_mutex_lock(&(sr->rt_lock));

        time_t current_time = time(NULL);
        struct sr_rt *rt_entry;
        struct sr_if *interface;

        /* 1. Check for expired entries and set metric to INFINITY */
        for (rt_entry = sr->routing_table; rt_entry; rt_entry = rt_entry->next) {
            if (current_time - rt_entry->updated_time >= 20) {
                rt_entry->metric = INFINITY;
            }
        }

        /* 2. Check interface status and update routing table */
        for (interface = sr->if_list; interface; interface = interface->next) {
            uint32_t interface_status = sr_obtain_interface_status(sr, interface->name);
            if (interface_status == 0) { /* Interface is down */
                /* Remove routes using this interface */
                for (rt_entry = sr->routing_table; rt_entry; rt_entry = rt_entry->next) {
                    if (strcmp(rt_entry->interface, interface->name) == 0) {
                        rt_entry->metric = INFINITY;
                    }
                }
            } else { /* Interface is up */
                /* Check if the directly connected subnet is in the routing table */
                int found = 0;
                for (rt_entry = sr->routing_table; rt_entry; rt_entry = rt_entry->next) {
                    if (rt_entry->dest.s_addr == (interface->ip & interface->mask)) {
                        rt_entry->updated_time = current_time;
                        found = 1;
                        break;
                    }
                }
                if (!found) {
                    struct in_addr dest_addr;
                    dest_addr.s_addr = interface->ip & interface->mask; 
                    struct in_addr gw_addr;
                    memset(&gw_addr, 0, sizeof(struct in_addr)); 
                    struct in_addr mask_addr;
                    mask_addr.s_addr = interface->mask;
                    sr_add_rt_entry(sr, dest_addr, gw_addr, mask_addr, 1, interface->name); 
                }

            }
        }

        /* 3. Send RIP response on all interfaces */
        printf("send normal RIP update\n");
        send_rip_update(sr);

        pthread_mutex_unlock(&(sr->rt_lock));
    }
    return NULL;
}

void send_rip_request(struct sr_instance *sr){
    struct sr_if* current_interface;
    for (current_interface = sr->if_list; current_interface; current_interface = current_interface->next) {
        uint8_t* rip_request = (uint8_t*) malloc(sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_udp_hdr_t)+sizeof(sr_rip_pkt_t));
        sr_ethernet_hdr_t* ethernet_header = (sr_ethernet_hdr_t*) rip_request;
        sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*)(rip_request+sizeof(sr_ethernet_hdr_t));
        sr_udp_hdr_t* udp_header = (sr_udp_hdr_t*)(rip_request+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
        sr_rip_pkt_t* rip_packet = (sr_rip_pkt_t*)(rip_request+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_udp_hdr_t));

        uint8_t broadcast_address[ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
        memcpy(ethernet_header->ether_dhost, broadcast_address, ETHER_ADDR_LEN);
        memcpy(ethernet_header->ether_shost, current_interface->addr, ETHER_ADDR_LEN);
        ethernet_header->ether_type = htons(ethertype_ip);

        ip_header->ip_hl = 5;
        ip_header->ip_v = 4;
        ip_header->ip_tos = 0;
        ip_header->ip_len = htons(sizeof(sr_ip_hdr_t)+sizeof(sr_udp_hdr_t)+sizeof(sr_rip_pkt_t));
        ip_header->ip_p = ip_protocol_udp;
        ip_header->ip_dst = htonl(0xFFFFFFFF);
        uint32_t interface_ip = current_interface->ip;
        ip_header->ip_src = interface_ip;
        ip_header->ip_ttl = 64;
        ip_header->ip_sum = 0;
        ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));

        udp_header->port_src = htons(520);
        udp_header->port_dst = htons(520);
        udp_header->udp_len = htons(sizeof(sr_udp_hdr_t)+sizeof(sr_rip_pkt_t));
        udp_header->udp_sum = 0;
        udp_header->udp_sum = cksum(udp_header, sizeof(sr_udp_hdr_t));

        rip_packet->command = 1;
        rip_packet->version = 2;
        int i;
        for (i = 0; i < MAX_NUM_ENTRIES; i++) {
            rip_packet->entries[i].afi = htons(AF_INET);
            rip_packet->entries[i].tag = 0;
            rip_packet->entries[i].address = 0;
            rip_packet->entries[i].mask = 0;
            rip_packet->entries[i].next_hop = 0;
            rip_packet->entries[i].metric = 0;
        }
        sr_send_packet(sr, rip_request, sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_udp_hdr_t)+sizeof(sr_rip_pkt_t), current_interface->name);
    }
}

void send_rip_update(struct sr_instance *sr){
    pthread_mutex_lock(&(sr->rt_lock));

    struct sr_if* current_interface;
    for (current_interface = sr->if_list; current_interface; current_interface = current_interface->next) {
        uint8_t* rip_response = (uint8_t*) malloc(sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_udp_hdr_t)+sizeof(sr_rip_pkt_t));
        sr_ethernet_hdr_t* ethernet_header = (sr_ethernet_hdr_t*) rip_response;
        sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*)(rip_response+sizeof(sr_ethernet_hdr_t));
        sr_udp_hdr_t* udp_header = (sr_udp_hdr_t*)(rip_response+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
        sr_rip_pkt_t* rip_packet = (sr_rip_pkt_t*)(rip_response+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_udp_hdr_t));

        uint8_t broadcast_address[ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
        memcpy(ethernet_header->ether_dhost, broadcast_address, ETHER_ADDR_LEN);
        memcpy(ethernet_header->ether_shost, current_interface->addr, ETHER_ADDR_LEN);
        ethernet_header->ether_type = htons(ethertype_ip);

        ip_header->ip_hl = 5;
        ip_header->ip_v = 4;
        ip_header->ip_tos = 0;
        ip_header->ip_len = htons(sizeof(sr_ip_hdr_t)+sizeof(sr_udp_hdr_t)+sizeof(sr_rip_pkt_t));
        ip_header->ip_p = ip_protocol_udp;
        ip_header->ip_dst = htonl(0xFFFFFFFF);
        uint32_t interface_ip = current_interface->ip;
        ip_header->ip_src = interface_ip;
        ip_header->ip_ttl = 64;
        ip_header->ip_sum = 0;
        ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));

        udp_header->port_src = htons(520);
        udp_header->port_dst = htons(520);
        udp_header->udp_len = htons(sizeof(sr_udp_hdr_t)+sizeof(sr_rip_pkt_t));
        udp_header->udp_sum = 0;
        udp_header->udp_sum = cksum(udp_header, sizeof(sr_udp_hdr_t));

        rip_packet->command = 2;
        rip_packet->version = 2;

        int i = 0;
        struct sr_rt* rt_entry;
        for (rt_entry = sr->routing_table; rt_entry && i < MAX_NUM_ENTRIES; rt_entry = rt_entry->next) {
            if (memcmp(&rt_entry->gw.s_addr, &current_interface->ip, sizeof(uint32_t)) == 0) {
                printf("split horizon on RT entry for %d\n", rt_entry->gw.s_addr);
                continue;
            }
            rip_packet->entries[i].afi = htons(AF_INET);
            rip_packet->entries[i].tag = 0;
            rip_packet->entries[i].address = rt_entry->dest.s_addr;
            rip_packet->entries[i].mask = rt_entry->mask.s_addr;
            rip_packet->entries[i].next_hop = rt_entry->gw.s_addr;
            rip_packet->entries[i].metric = htonl(rt_entry->metric);
            i++;
        }

        sr_send_packet(sr, rip_response, sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_udp_hdr_t)+sizeof(sr_rip_pkt_t), current_interface->name);
    }
    pthread_mutex_unlock(&(sr->rt_lock));
}

void update_route_table(struct sr_instance *sr, 
                        sr_ip_hdr_t* ip_packet,
                        sr_rip_pkt_t* rip_packet,
                        char* iface){
    pthread_mutex_lock(&(sr->rt_lock));
    /* Fill your code here */
    int changed = 0;
    int i;
    for (i = 0; i < MAX_NUM_ENTRIES; i++) {
        struct entry rip_entry = rip_packet->entries[i];
        uint32_t entry_metric = ntohl(rip_entry.metric);
        /* printf("rip_entry.metric: %d, ntohl(rip_entry.metric): %d\n\n", rip_entry.metric, entry_metric); */
        if (entry_metric == INFINITY) continue;

        int metric = INFINITY;
        if (entry_metric+1 < INFINITY) metric = entry_metric+1;

        /* 1. find RIP entry's destination's routing table entry */
        struct sr_rt* rt_entry;
        for (rt_entry = sr->routing_table; rt_entry; rt_entry = rt_entry->next) {
            if (rip_entry.address == rt_entry->dest.s_addr) break;
        }
        if (rt_entry) {
            /* a. if RT doesn't contain distance to RIP entry's destination */
            if (rt_entry->metric == INFINITY) {
                printf("%s is adding a new distance to %d: %d\n", sr->host, rt_entry->dest.s_addr, metric);
                changed = 1;
                rt_entry->gw.s_addr = ip_packet->ip_src;
                rt_entry->mask.s_addr = rip_entry.mask;
                memcpy(rt_entry->interface, iface, sr_IFACE_NAMELEN);
                rt_entry->metric = metric;
                rt_entry->updated_time = time(NULL);
            }
            /* b. if RT contains a distance to the RIP entry's destination */
            else if (rt_entry->metric != INFINITY) {
                /* i. if RIP packet source is the current next hop to the destination */
                if (ip_packet->ip_src == rt_entry->gw.s_addr) {
                    if (rt_entry->metric > metric) {
                        printf("%s is replacing a distance to %d: %d\n", sr->host, rt_entry->dest.s_addr, metric);
                        changed = 1;
                        rt_entry->metric = metric;
                    }
                    rt_entry->updated_time = time(NULL);
                }
                /* ii. if RIP packet source is not the current next hop to the destination*/
                else if (ip_packet->ip_src != rt_entry->gw.s_addr) {
                    /* if new path is shorter */
                    if (rt_entry->metric > metric || (rt_entry->metric == 0 && rt_entry->gw.s_addr != 0)) { /* NOTE: 2nd statement may be wrong */
                        if (rt_entry->metric == 0) {
                            printf("current distance to %d is 0\n", rt_entry->dest.s_addr);
                        }
                        printf("%s is creating new path to %d: %d\n", sr->host, rt_entry->dest.s_addr, metric);
                        changed = 1;
                        rt_entry->gw.s_addr = ip_packet->ip_src;
                        rt_entry->mask.s_addr = rip_entry.mask;
                        memcpy(rt_entry->interface, iface, sr_IFACE_NAMELEN);
                        rt_entry->metric = metric;
                        rt_entry->updated_time = time(NULL);
                    }
                    /* if new path is not shorter */
                    else if (rt_entry->metric <= metric) {
                        /* do nothing */
                    }
                }
            }
        }
    }
    pthread_mutex_unlock(&(sr->rt_lock));
    /* 2. */
    if (changed) {
        send_rip_update(sr);
    }
}