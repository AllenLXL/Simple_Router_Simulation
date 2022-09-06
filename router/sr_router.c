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

void sr_init(struct sr_instance *sr) {
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

void sr_handlepacket(struct sr_instance *sr,
                     uint8_t *packet/* lent */,
                     unsigned int len,
                     char *interface/* lent */) {
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    printf("*** -> Received packet of length %d \n", len);

    /* fill in code here */
    uint16_t ether_type = ethertype(packet);
    //  arp
    if (ether_type == ethertype_arp) {
        handle_arp(sr, packet, len, interface);
    } else if (ether_type == ethertype_ip) {
        // ip
        handle_ip(sr, packet, len, interface);
    }
}
// todo return type
void handle_arp(struct sr_instance *sr,
                uint8_t *packet,
                unsigned int len,
                char *interface) {
    sr_arp_hdr_t *arp_hrd = (sr_arp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
    // if op code is request
    if (ntohs(arp_hrd->ar_op) == arp_op_request) {
        struct sr_if *sr_if = sr_get_interface(sr, interface);
        if (sr_if != 0) { // found interface
            // construct and fill up ethernet preamble
            sr_ethernet_hdr_t *ether_arp = malloc(sizeof(struct sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
            memcpy(ether_arp->ether_dhost, arp_hrd->ar_sha, ETHER_ADDR_LEN);
            memcpy(ether_arp->ether_shost, sr_if->addr, ETHER_ADDR_LEN);
            ether_arp->ether_type = htons(ethertype_arp);

            // shift pointer to data area of ethernet preamble
            sr_arp_hdr_t *arp_only = (struct sr_arp_hdr_t *) ((uint8_t *) ether_arp + sizeof(struct sr_ethernet_hdr_t));
            // fill arp packet
            arp_only->ar_hrd = arp_hrd->ar_hrd;
            arp_only->ar_pro = arp_hrd->ar_pro;
            arp_only->ar_hln = arp_hrd->ar_hln;
            arp_only->ar_pln = arp_hrd->ar_pln;
            arp_only->ar_op = htons(arp_op_reply);

            // fill arp packet
            memcpy(arp_only->ar_sha, sr_if->addr, ETHER_ADDR_LEN);
            arp_only->ar_sip = sr_if->ip;
            memcpy(arp_only->ar_tha, arp_hrd->ar_sha, ETHER_ADDR_LEN);
            arp_only->ar_tip = arp_hrd->ar_sip;

            // send arp reply
            int res = sr_send_packet(sr, (uint8_t *) ether_arp, len, interface);

            // free malloc (borrowed stuff)
            free(arp_reply);

            // send packet result
            return res;
        }
        // if op code is reply
    } else if (ntohs(arp_hrd->ar_op) == arp_op_reply) {
        struct sr_arpcache *cache = &(sr->cache);
        // add ip to mac to arp chche
        // note it has lock
        pthread_mutex_lock(&(cache->lock));
        struct sr_arpreq *arpreq = sr_arpcache_insert(cache,
                                                      (unsigned char *) arp_hrd->sha,
                                                      (uint32_t) arp_hrd->sip);
        // send off packet waiting for this arp reply
        if (arpreq) {
            struct sr_packet *pkt = arpreq->packets;
            while (pkt) {
                struct sr_ethernet_hdr *ether_frame = (sr_ethernet_hdr_t *) (pkt->buf);
                memcpy(ether_frame->ether_frame, arp_hrd->sha, ETHER_ADDR_LEN);
                sr_send_packet(sr, (uint8_t *) ether_frame, len, pkt->iface);
                pkt = pkt->next;
            }
            sr_arpreq_destroy(cache, arpreq);
        }
        // unlock
        pthread_mutex_unlock(&(cache->lock));
        return;
    }

}

void handle_ip(struct sr_instance *sr,
                uint8_t *packet,
                unsigned int len,
                char *interface){
    sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
    // check sum
    uint16_t ip_header_sum = ip_hdr->ip_sum;
    ip_hdr->ip_sum = 0x0000;
    uint16_t calculated_sum = cksum(ip_hdr, sr_ip_hdr->ip_hl*4); // 1 hex 4 bit
    ip_hdr->ip_sum = calculated_sum;
    if (ip_header_sum != calculated_sum){
        return;
    }

    if (sr_get_interface_ip(sr, ip_hdr->ip_dst)) {
        if (ip_hdr->ip_p == ip_protocol_icmp){
            uint8_t* packet_reply;
            struct sr_icmp_hdr_t* icmp_hdr = (struct sr_icmp_hdr*)((uint8_t*)ip_hdr + sizeof(struct sr_ip_hdr));
            if (icmp_hdr->icmp_type == 8) { //icmp echo request NOTE we only need to deal with echo request
    //            uint8_t* packet_back = (uint8_t*) malloc(sizeof(sr_ip_hdr)+sizeof(sr_ethernet_hdr)+sizeof(sr_icmp_t0_hdr));
                packet_reply = (uint8_t*) malloc(len);
                // find next hop ip lpm todo free target_rt
                sr_rt* target_rt = lfm(ip_hdr->ip_dst, sr);

                // get next hop ip and interface name
                uint32_t next_hop_ip = target_rt->gw.s_addr;
                char if_gw[sr_IFACE_NAMELEN];
                memcpy(if_gw, target_rt->interface, sr_IFACE_NAMELEN);

                // send back icmp echo reply
                // ether header
                sr_ethernet_hdr_t* ether_hdr = (sr_ethernet_hdr_t*) packet_reply;
                ether_hdr->ether_type = ethertype(packet);
                memcpy(ether_hdr->ether_dhost, sr_if->addr, ETHER_ADDR_LEN);
                memcpy(ether_hdr->ether_shost, ether_hdr->ether_dhost, ETHER_ADDR_LEN);
                // ip header
                sr_ip_hdr_t* reply_ip_hdr = (sr_ip_hdr_t*) (ether_hdr + sizeof(sr_ethernet_hdr_t));
                reply_ip_hdr->ip_hl = ip_hdr->ip_hl; reply_ip_hdr->ip_v = ip_hdr->ip_v;
                reply_ip_hdr->ip_tos = ip_hdr->ip_tos;
                reply_ip_hdr->ip_len = ip_hdr->ip_len;
                // todo fill below ip_src may need change
                //reply_ip_hdr->ip_id =
                //reply_ip_hdr->ip_off =
                //reply_ip_hdr->ip_ttl =
                reply_ip_hdr->ip_p = ip_protocol_icmp;
                reply_ip_hdr->ip_src = ip_hdr->ip_dst;
                reply_ip_hdr->ip_dst = sr_if->ip;
                reply_ip_hdr->ip_sum = 0;
                reply_ip_hdr->ip_sum = cksum(reply_ip_hdr, sizeof(sr_ip_hdr_t));
                // icmp header
                sr_icmp_hdr_t* echo_reply_icmp_hdr = (sr_icmp_hdr_t*) reply_ip_hdr + sizeof(sr_ip_hdr_t);
                echo_reply_icmp_hdr->icmp_type = 0;
                echo_reply_icmp_hdr->icmp_code = 0;
                memcpy((uint8_t*)echo_reply_icmp_hdr + sizeof(sr_icmp_hdr), (uint8_t*)icmp_hdr + sizeof(sr_icmp_hdr), ICMP_DATA_SIZE);
                // todo no nned to cksum ???
                echo_reply_icmp_hdr->icmp_sum = 0;
                echo_reply_icmp_hdr->icmp_sum = cksum(echo_reply_icmp_hdr,sizeof(echo_reply_icmp_hdr));
            } else{ // only echo request
                return;
            }
        } else{ // tcp udp generate ICMP port unreachable
            //Sent if there is a non-existent route to the destination IP (no matching entry in routing table when forwarding an
            //IP packet).
            // icmp port unreachable

            // find next hop ip lpm todo free target_rt
            sr_rt* target_rt = lfm(ip_hdr->ip_dst, sr);

            // get next hop ip and interface name
            uint32_t next_hop_ip = target_rt->gw.s_addr;
            char if_gw[sr_IFACE_NAMELEN];
            memcpy(if_gw, target_rt->interface, sr_IFACE_NAMELEN);
            icmp_unreachable(sr, packet,len,interface,if_gw, 3);
        }
    } else{ // ip destination not found for me; for someone else
        // todo ttl and eventually drop

        // if ttl = 1 icmp time exceeded
        if (ip_hdr->ttl - 1 <= 0){
            uint32_t ip_dst_addr = ip_hrd->src;

            // lfm todo free target_rt
            sr_rt* target_rt = lfm(ip_dest_addr, sr);
            char if_gw[sr_IFACE_NAMELEN];
            memcpy(if_gw, target_rt->interface, sr_IFACE_NAMELEN);
            // todo type 11
            icmp_unreachable(sr, packet,len,interface,if_gw, 0);
        } else {
            ip_hdr->ttl -= 1;
            ip_hdr->ip_sum = 0;
            ip->sum = cksum(ip_hdr, sizeof(ip_hdr));
            uint32_t ip_dst_addr = ip_hrd->dst;
            if (!lfm(ip_dst_addr, sr)){
                ip_dst_addr = ip_hrd->src;
                sr_rt* target_rt = lfm(ip_dest_addr, sr);
                char if_gw[sr_IFACE_NAMELEN];
                memcpy(if_gw, target_rt->interface, sr_IFACE_NAMELEN);
                // net unreachable
                icmp_unreachable(sr, packet,len,interface,if_gw, 0);
            } else{
                // lfm todo free target_rt
                sr_rt* target_rt = lfm(ip_dst_addr, sr);
                char if_gw[sr_IFACE_NAMELEN];
                memcpy(if_gw, target_rt->interface, sr_IFACE_NAMELEN);

                sr_if* reply_if = sr_get_interface(sr, if_gw);

            }
        }


    }

}

// icmp unreachable
void icmp_unreachable(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *in_interface, char *out_interface, int code){
    uint8_t *packet_back = (uint8_t *)malloc(sizeof(sr_icmp_t3_hdr)+sizeof(sr_ip_hdr_t)+sizeof(sr_ethernet_hdr_t));
    sr_if* income_if = sr_get_interface(sr, interface);
    sr_ethernet_hdr_t* income_ether_hdr = (sr_ethernet_hdr_t*) packet;
    sr_ip_hdr_t* income_ip_hdr = (sr_ip_hdr_t*) income_ether_hdr+sizeof(sr_ethernet_hdr_t);
    sr_if* out_if = sr_get_interface(sr, out_interface);

    // ethernet hdr
    sr_ethernet_hdr_t* ether_hdr_back = (sr_ethernet_hdr_t*) packet_back;
    ether_hdr_back->ether_type=ethertype_ip;
    memcpy(ether_hdr_back->ether_dhost, income_ether_hdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(ether_hdr_back->ether_shost, income_if->addr, ETHER_ADDR_LEN);
    // ip hdr
    sr_ip_hdr_t* ip_hdr_back = (sr_ip_hdr_t*) ether_hdr_back+sizeof(sr_ethernet_hdr_t);
    ip_hdr_back->ip_hl = income_ip_hdr->ip_hl; reply_ip_hdr->ip_v = income_ip_hdr->ip_v;
    ip_hdr_back->ip_tos = ip_hdr->ip_tos;
    ip_hdr_back->ip_len = ip_hdr->ip_len;
    // todo fill below ip_src may need change
    //ip_hdr_back->ip_id =
    //ip_hdr_back->ip_off =
    //ip_hdr_back->ip_ttl =
    ip_hdr_back->ip_p = ip_protocol_icmp;
    ip_hdr_back->ip_src = out_if->ip;
    ip_hdr_back->ip_dst = sr_if->ip;
    ip_hdr_back->ip_sum = 0;
    ip_hdr_back->ip_sum = cksum(ip_hdr_back, sizeof(sr_ip_hdr_t));

    // icmp hdr
    sr_icmp_t3_hdr_t* icmp_t3_hdr = (sr_icmp_t3_hdr_t*) ip_hdr_back + sizeof(sr_ip_hdr_t);
    icmp_t3_hdr->icmp_type = 3;
    icmp_t3_hdr->icmp_code = code;
    icmp_t3_hdr->icmp_sum=0;
    icmp_t3_hdr->unused=0;
    icmp_t3_hdr->next_mtu=0;
    memcpy(icmp_t3_hdr->data, income_ip_hdr, 20); // todo not sure ip header and what
    memcpy(icmp_t3_hdr->data, packet, 8);
    icmp_t3_hdr->icmp_sum=cksum(icmp_t3_hdr, sizeof(sr_icmp_t3_hdr_t));
    // send back
}

// longest prefix match function, given destination ip and sr(eventually routing table)
sr_rt* lfm(uint32_t* ip_dst, struct sr_instance* sr){
    sr_rt* target_rt = malloc(sizeof(struct sr_rt));
    int found = 0;
    uint32_t cur_mask = 0;
    for (sr_rt* loop_ent=sr->routing_table; loop_ent; loop_ent=loop_ent->next){
        uint32_t mask_addr = loop_ent->mask.s_addr;
        uint32_t dest_addr = loop_ent->dest.s_addr;
        if (mask_addr==0){
            memcpy(target_rt, loop_ent, sizeof(struct sr_rt));
            found = 1;
        }
        if ((dest_addr & mask_addr) == (ip_dst & mask_addr) && mask_addr > cur_mask){
            memcpy(target_rt, loop_ent, sizeof(struct sr_rt));
            cur_mask = mask_addr;
            found = 1;
        }
    }
    if (found){
        return target_rt;
    } else{
        free(target_rt);
        return NULL;
    }

}

