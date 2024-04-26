/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdbool.h> 
#include <stdlib.h>
#include <string.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */
    sr_load_rt(sr, "rtable");
    /*sr_print_routing_table(sr);*/

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void make_etherheader(
              sr_ethernet_hdr_t* ether_header,
              uint8_t*  host,    /* destination ethernet address */
              uint8_t*  dest, 
              uint16_t ether_type) {                                                /*Create a new buffer which will become the packet we send*/
  
  /* Ethernet header */
  memcpy(ether_header->ether_shost,  host, ETHER_ADDR_LEN); /* this is right*/
  memcpy(ether_header->ether_dhost, dest, ETHER_ADDR_LEN);      /* */
  ether_header->ether_type = ether_type;
  }

/*  Create ARP packet for requests and replies 
    NOTE: DOES NOT ESTABLISH ARP SECTIONS BEFORE OPCODE*/
void make_arp_packet(
              uint8_t* packet,
              bool reply, 
              uint8_t* sha,
              uint32_t sip, 
              uint8_t* tha,
              uint32_t tip) {

  /* Establish pointers for ethernet and ARP header starts */
  sr_ethernet_hdr_t* ethernet_header = (sr_ethernet_hdr_t*)packet;
  sr_arp_hdr_t* arp_header = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
  
  if (reply) {
    arp_header->ar_op = htons(arp_op_reply);
    make_etherheader(ethernet_header, sha, tha, (uint16_t)htons(ethertype_arp));
  } else {
    uint8_t broadcast[ETHER_ADDR_LEN];
    broadcast[0] = 0xff;
    broadcast[1] = 0xff;
    broadcast[2] = 0xff;
    broadcast[3] = 0xff;    
    broadcast[4] = 0xff;
    broadcast[5] = 0xff;
    arp_header->ar_op = htons(arp_op_request);
    make_etherheader(ethernet_header, sha, broadcast, (uint16_t)htons(ethertype_arp));
  }

  memcpy(arp_header->ar_sha, sha, ETHER_ADDR_LEN);
  arp_header->ar_sip = sip;
  memcpy(arp_header->ar_tha, tha, ETHER_ADDR_LEN);
  arp_header->ar_tip = tip;

  memcpy(packet, ethernet_header, sizeof(sr_ethernet_hdr_t));
  memcpy(packet + sizeof(sr_ethernet_hdr_t), arp_header, sizeof(sr_arp_hdr_t));
}

void make_icmp_header(
      sr_icmp_hdr_t* icmp_header,
      uint8_t type,
      uint8_t code)
{
  icmp_header->icmp_type = type;
  icmp_header->icmp_code = code;
  icmp_header->icmp_sum = 0;
}

void make_icmp3_packet (
  uint8_t* tosend, 
  struct sr_if* recieving_interface,
  sr_ethernet_hdr_t* ethernet_header,
  sr_ip_hdr_t* ip_header,
  uint8_t type,
  uint8_t code
  ) {
        sr_ethernet_hdr_t* ethernet_header_temp = malloc(sizeof(sr_ethernet_hdr_t));
        make_etherheader(ethernet_header_temp, recieving_interface->addr, ethernet_header->ether_shost, (uint16_t)htons(ethertype_ip));
        memcpy(tosend, ethernet_header_temp, sizeof(sr_ethernet_hdr_t));
        free(ethernet_header_temp);

        sr_ip_hdr_t* ip_header_temp = (sr_ip_hdr_t*)(tosend + sizeof(sr_ethernet_hdr_t));
        memcpy(ip_header_temp, ip_header, sizeof(sr_ip_hdr_t));
        ip_header_temp->ip_hl = 5;
        ip_header_temp->ip_v = 4;
        ip_header_temp->ip_tos = 0;
        ip_header_temp->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
        ip_header_temp->ip_p = ip_protocol_icmp;
        ip_header_temp->ip_dst = ip_header->ip_src;
        ip_header_temp->ip_src = recieving_interface->ip;
        ip_header_temp->ip_ttl = 64;
        ip_header_temp->ip_sum = 0x0000;
        ip_header_temp->ip_sum = cksum(ip_header_temp, sizeof(sr_ip_hdr_t));

        sr_icmp_t3_hdr_t* icmp_t3_header = (sr_icmp_t3_hdr_t*)(tosend + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        icmp_t3_header->icmp_type = type;
        icmp_t3_header->icmp_code = code;
        memcpy(icmp_t3_header->data, ip_header, ICMP_DATA_SIZE);
        icmp_t3_header->icmp_sum = 0;
        icmp_t3_header->icmp_sum = cksum(icmp_t3_header, sizeof(sr_icmp_t3_hdr_t));
  }

void handle_arpreq(struct sr_instance* sr, struct sr_arpreq* request) {
    if (difftime(time(NULL), request->sent) >= 1.0) {
        if (request->times_sent >= 5) {            
            struct sr_packet* next = request->packets;
            while (next != NULL) {
                /* Send host unreachable*/
                unsigned int len = sizeof(sr_ethernet_hdr_t)+ sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
                uint8_t* tosend = (uint8_t*)malloc(len);
                make_icmp3_packet(tosend, sr_get_interface(sr, next->iface), (sr_ethernet_hdr_t*)tosend, (sr_ip_hdr_t*)(tosend + sizeof(sr_ethernet_hdr_t)), 3, 1);
                sr_send_packet(sr, tosend, len, next->iface);
                free(tosend);
                next = next->next;
            }
            sr_arpreq_destroy(&sr->cache, request);
        } else {
           unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
            uint8_t* packet = malloc(len); 

            struct sr_if* iface = sr_get_interface(sr, request->packets->iface);
/*
            uint32_t mask = 0xffffffff;
            uint32_t mask_mod = 1;
            bool found = false;
            while(mask > 0 && !found) {
              iface = sr->if_list;
              while (iface != NULL) {
                if ((mask & iface->ip) == (mask & request->ip)) {
                  found = true;
                  break;
                }
                else {iface = iface->next;}
              }
              mask -= mask_mod;
              mask_mod = mask_mod << 1;
            }
*/

            uint8_t unknown_ha[ETHER_ADDR_LEN];
            unknown_ha[0] = 0x00;
            unknown_ha[1] = 0x00;
            unknown_ha[2] = 0x00;
            unknown_ha[3] = 0x00;    
            unknown_ha[4] = 0x00;
            unknown_ha[5] = 0x00;  

            sr_arp_hdr_t* arp_header = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

            arp_header->ar_hrd = htons(arp_hrd_ethernet);
            arp_header->ar_pro = htons(ethertype_ip);
            arp_header->ar_hln = ETHER_ADDR_LEN;
            arp_header->ar_pln = sizeof(uint32_t);

            make_arp_packet(packet, false, iface->addr, iface->ip, unknown_ha, request->ip);
            
            /*printf("sending packet\n");
            print_hdrs(packet, len);*/
            sr_send_packet(sr, packet, len, iface->name);
            time(&request->sent);
            request->times_sent++;
            free(packet);
        }
    }
}

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  /*printf("*** -> Received packet of length %d with type %d \n", len, ethertype(packet));

  print_hdrs(packet, len);*/

  sr_ethernet_hdr_t* ethernet_header = (sr_ethernet_hdr_t*)packet;
  struct sr_if* recieving_interface = sr_get_interface(sr, interface);
  
  /* Deal with ARP requests*/
  if (ethertype(packet) == ethertype_arp) {                               
      sr_arp_hdr_t* arp_header = (sr_arp_hdr_t*)(packet+(sizeof(*ethernet_header)));  
      if (arp_header->ar_op == htons(arp_op_request)) {                                    /* Deal with ARP requests*/
          struct sr_if* current_interface = sr->if_list;
          while (current_interface != NULL) {                                       /*Iterate through router interfaces to see if any interface ips match the request IP*/
              if (current_interface->ip == arp_header->ar_tip) {

                uint8_t* tosend = malloc(len);                                                 /*Create a new buffer which will become the packet we send*/
                memcpy(tosend, packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
                
                make_arp_packet(tosend, true, (uint8_t*)&current_interface->addr, current_interface->ip, (uint8_t*)&arp_header->ar_sha, arp_header->ar_sip);
                
                /*print_hdrs(tosend, len);*/
                sr_send_packet(sr, tosend, len, interface);

                sr_arpcache_insert(&sr->cache, arp_header->ar_sha, arp_header->ar_sip);
                free(tosend);

                return;
              }
              current_interface = current_interface->next;
          }
      } 
      
      /*TODO handle ARP relply to a request that you sent 
      once you get a reply, go through the arpcashe and send the waiting packets*/
      
      else if (arp_header->ar_op == htons(arp_op_reply)){
        printf("replied");
        struct sr_arpreq* waiting_packets = sr_arpcache_insert(&sr->cache, arp_header->ar_sha, arp_header->ar_sip);
        struct sr_packet* queue_packet = waiting_packets->packets;
        while (queue_packet != NULL) {
            uint8_t* tosend = queue_packet->buf;
            sr_ethernet_hdr_t* modify_header = (sr_ethernet_hdr_t*)tosend;
            sr_ip_hdr_t* modify_ip = (sr_ip_hdr_t*)(tosend + sizeof(sr_ethernet_hdr_t));
            memcpy(modify_header->ether_dhost, arp_header->ar_sha, ETHER_ADDR_LEN);
            memcpy(modify_header->ether_shost, recieving_interface->addr, ETHER_ADDR_LEN);
            modify_ip->ip_ttl = modify_ip->ip_ttl - 1;
            modify_ip->ip_sum = 0;
            modify_ip->ip_sum = cksum(modify_ip, sizeof(sr_ip_hdr_t));
            sr_send_packet(sr, tosend, queue_packet->len, recieving_interface->name);
            queue_packet = queue_packet->next;
        }
        sr_arpreq_destroy(&sr->cache, waiting_packets);
        return;
      } 
  }
    /* Deal with IP packets*/  
  else if (ethertype(packet) == ethertype_ip) {

    sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
    /* handle RIP packets HERE*/
    if (ip_header->ip_dst == 0xFFFFFFFF) {
      sr_udp_hdr_t* udp_header = (sr_udp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
      if (ip_header->ip_p == ip_protocol_udp) {
        if (ntohs(udp_header->port_src) == 520 && ntohs(udp_header->port_dst) == 520) { /* if this is true, then it is RIP packet*/
          sr_rip_pkt_t* rip_packet = (sr_rip_pkt_t*)(packet+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_udp_hdr_t));
          if (rip_packet->command == 1) {
            printf("sr_handle_packet(): %s receiving an RIP request and is sending a response\n", sr->host);
            send_rip_update(sr);
          } 
          else if (rip_packet->command == 2) {
            printf("sr_handle_packet(): %s receiving an RIP response and is updating its routing table\n", sr->host);
            update_route_table(sr, ip_header, rip_packet, interface);
          }
        }  
      }
      else {
        /* send port unreachable packet back to the source IP */
        uint8_t* tosend_t33 = malloc(sizeof(sr_ethernet_hdr_t)+ sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
        memset(tosend_t33, 0, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));

        make_icmp3_packet(tosend_t33, recieving_interface, ethernet_header, ip_header, 3, 3);

        /*print_hdrs(tosend_t33, sizeof( sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t)));*/

        sr_send_packet(sr, tosend_t33, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), interface);
        free(tosend_t33);
        return;
      }
    }

    /*Check if packet is adressed to one of this server's interfaces*/ 
    struct sr_if* current_interface = sr->if_list;
    while (current_interface != NULL) {                                       /*Iterate through router interfaces to see if any interface ips match the request IP*/
        if (current_interface->ip == ip_header->ip_dst) {
          /* UPDATED RIP check using sr_obtain_interface_status */
          if (!sr_obtain_interface_status(sr, current_interface->name)) {
            uint8_t* tosend_t30 = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
            memset(tosend_t30, 0, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
            
            make_icmp3_packet(tosend_t30, recieving_interface, ethernet_header, ip_header, 3, 0);
          
            /*print_hdrs(tosend_t30, len);*/
            sr_send_packet(sr, tosend_t30, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), current_interface->name);
            free(tosend_t30);
            return;
          }
          /* Deal with ICMP packets*/
          if (ip_header->ip_p == ip_protocol_icmp) {
            sr_icmp_hdr_t* icmp_header = (sr_icmp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
            /*printf("%d\n", sizeof(sr_ip_hdr_t)); + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t));*/
            /* Deal with type 3 ICMP packets*/ 
            if (icmp_header->icmp_type == 0x03){
            } 
            /* Deal with all other ICMP packet types*/
            else {
              /* echo request */
              if (icmp_header->icmp_type == 0x08){
                uint8_t* tosend_t8 = malloc(len);

                sr_ethernet_hdr_t* ethernet_header_t8 = malloc(sizeof(sr_ethernet_hdr_t));
                make_etherheader(ethernet_header_t8, recieving_interface->addr, ethernet_header->ether_shost, (uint16_t)htons(ethertype_ip));
                memcpy(tosend_t8, ethernet_header_t8, sizeof(sr_ethernet_hdr_t));
                free(ethernet_header_t8);

                /*!!!! perhaps need to set ttl to 64 or sm first !!!!*/
            
                /*ip_header->ip_len = 0x5410;*/
                uint32_t save =  ip_header->ip_dst;
                ip_header->ip_dst = ip_header->ip_src;
                ip_header->ip_src = save;
                ip_header->ip_sum = 0x0000;
                ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));
                memcpy(tosend_t8 + sizeof(sr_ethernet_hdr_t), ip_header, sizeof(sr_ip_hdr_t));

                /*sr_icmp_hdr_t* icmp_header_t8 = malloc(sizeof(sr_icmp_hdr_t));*/
                make_icmp_header(icmp_header, 0, 0);
                icmp_header->icmp_sum = cksum(icmp_header, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
                memcpy(tosend_t8 + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), icmp_header, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
                /*memcpy(tosend_t8 + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), icmp_header_t8, sizeof(sr_icmp_hdr_t));*/
                /*free(icmp_header_t8);*/
                
                sr_send_packet(sr, tosend_t8, len, interface);
                free(tosend_t8);
                return;
              }
            }
          }
          else if (ip_header->ip_p == ip_protocol_tcp || ip_header->ip_p == ip_protocol_udp) {
            /* send port unreachable packet back to the source IP */
            uint8_t* tosend_t33 = malloc(sizeof(sr_ethernet_hdr_t)+ sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
            memset(tosend_t33, 0, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));

            make_icmp3_packet(tosend_t33, recieving_interface, ethernet_header, ip_header, 3, 3);

            /*print_hdrs(tosend_t33, sizeof( sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t)));*/

            sr_send_packet(sr, tosend_t33, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), interface);
            free(tosend_t33);
            return;

          }
        }
      current_interface = current_interface->next;
    }

    /* send ttl exceeded error if it is not adressed to you, MAY NEED TO ADD THIS FOR IF IT IS ADRESSED TO YOU AND TTL = 0*/
    if (ip_header->ip_ttl <= 1){
        uint8_t* tosend_t11 = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
        memset(tosend_t11, 0, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
        
        make_icmp3_packet(tosend_t11, recieving_interface, ethernet_header, ip_header, 11, 0);

        /*print_hdrs(tosend_t11, len);*/
        sr_send_packet(sr, tosend_t11, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), interface);
        free(tosend_t11);
        return; 

    }

    
    /*See if target ip matches the destination ip of any of my interfaces*/
    struct sr_rt* my_routing_table = sr->routing_table;
    struct sr_rt* table_entry_tosend = NULL;
    while (my_routing_table != NULL) {
      if (my_routing_table->dest.s_addr == ip_header->ip_dst) {
          table_entry_tosend = my_routing_table;
          break;
      } 
      my_routing_table = my_routing_table->next;
    }

    /*send destination net unreachable error if it doest not match any interface*/
    if (table_entry_tosend == NULL) {
        uint8_t* tosend_t30 = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
        memset(tosend_t30, 0, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
        
        make_icmp3_packet(tosend_t30, recieving_interface, ethernet_header, ip_header, 3, 0);
      
        /*print_hdrs(tosend_t30, len);*/
        sr_send_packet(sr, tosend_t30, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), interface);
        free(tosend_t30);
        return; 
    }

    /* forward if it does match an interface */
    else {
      /* updated RIP forwarding logic HERE */
      if (!sr_obtain_interface_status(sr, table_entry_tosend->interface)) {
        uint8_t* tosend_t30 = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
        memset(tosend_t30, 0, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
        
        make_icmp3_packet(tosend_t30, recieving_interface, ethernet_header, ip_header, 3, 0);
      
        /*print_hdrs(tosend_t30, len);*/
        sr_send_packet(sr, tosend_t30, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), interface);
        free(tosend_t30); /* destination NET unreachable*/
        return; 
      }
      /* sr_arpcache_dump(&sr->cache); */
      uint32_t next_hop_ip = (table_entry_tosend->gw.s_addr == 0) ? ip_header->ip_dst : table_entry_tosend->gw.s_addr; /* UPDATED CODE: per the instructions use dest IP address to find eth_dst MAC address */
      struct sr_arpentry* entry = sr_arpcache_lookup(&sr->cache, next_hop_ip);
      struct sr_if* interface_tosend = sr_get_interface(sr, table_entry_tosend->interface);

      if (entry == NULL){
        struct sr_arpreq* req = sr_arpcache_queuereq(&sr->cache, next_hop_ip, packet, len, table_entry_tosend->interface);
        handle_arpreq(sr, req);
      }

      /*forward IP packet if the mac adress coressponding to the desired ip adress exists*/
      else {
        memcpy(ethernet_header->ether_dhost, entry->mac, ETHER_ADDR_LEN);
        memcpy(ethernet_header->ether_shost, interface_tosend->addr, ETHER_ADDR_LEN);
        ip_header->ip_ttl = ip_header->ip_ttl - 1;
        ip_header->ip_sum = 0;
        ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));
        sr_send_packet(sr, packet, len, interface_tosend->name);
        free(entry);
      }
    }  
  }
  /* fill in code here */
}/* end sr_ForwardPacket */
