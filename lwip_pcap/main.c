/*
 * Copyright (c) 2001-2003 Swedish Institute of Computer Science.
 * All rights reserved. 
 * 
 * Redistribution and use in source and binary forms, with or without modification, 
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED 
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT 
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, 
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT 
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING 
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY 
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 * 
 * Author: Erik Ekman <erik@kryo.se>
 *
 */
#include "pcap.h"

#include <Windows.h>


#include "lwip/init.h"
#include "lwip/netif.h"
#include "lwip/dns.h"
#include "netif/etharp.h"
#if LWIP_IPV6
#include "lwip/ethip6.h"
#include "lwip/nd6.h"
#endif

#include "lwip/apps/httpd.h"
//#include "lwip/apps/snmp.h"
//#include "lwip/apps/lwiperf.h"
//#include "lwip/apps/mdns.h"
//#include "lwip/apps/netbiosns.h"


#include <string.h>
#include <stdio.h>


/* This define enables multi packet processing.
 * For this, the input is interpreted as 2 byte length + data + 2 byte length + data...
 * #define LWIP_FUZZ_MULTI_PACKET
*/
u8_t pktbuf[20000];

pcap_t *pcap_fp;

/* no-op send function */
static err_t lwip_tx_func(struct netif *netif, struct pbuf *p)
{
  BYTE *pbuf;
  int i;
  int cnt = 0;
  err_t err = ERR_OK;

  LWIP_UNUSED_ARG(netif);

  while( p != NULL ) {
	  pbuf = (BYTE*)p->payload;
	  if ((p->len + cnt) > sizeof(pktbuf)) {
		  err = ERR_BUF;
		  break;
	  }
	  for( i =0 ; i < p->len; i++ ){
		  printf("%02X ", pbuf[i]);
		  if ( (i % 16) == 15) printf("\n");
		  pktbuf[cnt++] = pbuf[i];
	  }
	  p = p->next;
  }
  printf( "\n");
  pcap_sendpacket(pcap_fp,	// Adapter
		pktbuf,				// buffer with the packet
		cnt					// size
		);
  return err;
}

static err_t testif_init(struct netif *netif)
{
  netif->name[0] = 'f';
  netif->name[1] = 'z';
  netif->output = etharp_output;
  netif->linkoutput = lwip_tx_func;
  netif->mtu = 1500;
  netif->hwaddr_len = 6;
  netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_IGMP;

  netif->hwaddr[0] = 0x00;
  netif->hwaddr[1] = 0x23;
  netif->hwaddr[2] = 0xC1;
  netif->hwaddr[3] = 0xDE;
  netif->hwaddr[4] = 0xD0;
  netif->hwaddr[5] = 0x0D;

#if LWIP_IPV6
  netif->output_ip6 = ethip6_output;
  netif->ip6_autoconfig_enabled = 1;
  netif_create_ip6_linklocal_address(netif, 1);
  netif->flags |= NETIF_FLAG_MLD6;
#endif

  return ERR_OK;
}

static void input_pkt(struct netif *netif, const u8_t *data, size_t len)
{
  struct pbuf *p, *q;
  err_t err;

  if (netif->input != NULL) {
	  LWIP_ASSERT("pkt too big", len <= 0xFFFF);
	  p = pbuf_alloc(PBUF_RAW, (u16_t)len, PBUF_POOL);
	  LWIP_ASSERT("alloc failed", p);
	  for (q = p; q != NULL; q = q->next) {
		  MEMCPY(q->payload, data, q->len);
		  data += q->len;
	  }
	  err = netif->input(p, netif);
	  if (err != ERR_OK) {
		  pbuf_free(p);
	  }
  }
}

static void input_pkts(struct netif *netif, const u8_t *data, size_t len)
{
  input_pkt(netif, data, len);
}

u32_t sys_now(void)
{
	return GetTickCount();
}

void * sio_open(u8_t devnum)
{
	return NULL;
}

void sio_send(u8_t c, void* fd)
{
}

u32_t sio_tryread(void* fd, u8_t *data, u32_t len)
{
	return 0;
}



/* 4 bytes IP address */
typedef struct ip_address
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

/* IPv4 header */
typedef struct ip_header
{
	u_char	ver_ihl;		// Version (4 bits) + Internet header length (4 bits)
	u_char	tos;			// Type of service 
	u_short tlen;			// Total length 
	u_short identification; // Identification
	u_short flags_fo;		// Flags (3 bits) + Fragment offset (13 bits)
	u_char	ttl;			// Time to live
	u_char	proto;			// Protocol
	u_short crc;			// Header checksum
	ip_address	saddr;		// Source address
	ip_address	daddr;		// Destination address
	u_int	op_pad;			// Option + Padding
}ip_header;

/* UDP header*/
typedef struct udp_header
{
	u_short sport;			// Source port
	u_short dport;			// Destination port
	u_short len;			// Datagram length
	u_short crc;			// Checksum
}udp_header;

/* prototype of the packet handler */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

pcap_if_t *alldevs;
pcap_if_t *d;
int inum;
int i=0;
pcap_t *adhandle;
char errbuf[PCAP_ERRBUF_SIZE];
u_int netmask;
//char packet_filter[] = "ip and udp";
char packet_filter[] = "";
struct bpf_program fcode;

#ifdef _WIN32
#include <tchar.h>
BOOL LoadNpcapDlls()
{
	_TCHAR npcap_dir[512];
	UINT len;
	len = GetSystemDirectory(npcap_dir, 480);
	if (!len) {
		fprintf(stderr, "Error in GetSystemDirectory: %x", GetLastError());
		return FALSE;
	}
	_tcscat_s(npcap_dir, 512, _T("\\Npcap"));
	if (SetDllDirectory(npcap_dir) == 0) {
		fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
		return FALSE;
	}
	return TRUE;
}
#endif

int pcap_init()
{

#ifdef _WIN32
	/* Load Npcap and its functions. */
	if (!LoadNpcapDlls())
	{
		fprintf(stderr, "Couldn't load Npcap\n");
		exit(1);
	}
#endif

	/* Retrieve the device list */
	if(pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	
	/* Print the list */
	for(d=alldevs; d; d=d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if(i==0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}
	
	printf("Enter the interface number (1-%d):",i);
	scanf("%d", &inum);
	
	/* Check if the user specified a valid adapter */
	if(inum < 1 || inum > i)
	{
		printf("\nAdapter number out of range.\n");
		
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
	
	/* Open the adapter */
	if ((pcap_fp = adhandle= pcap_open_live(d->name,	// name of the device
							 65536,			// portion of the packet to capture. 
											// 65536 grants that the whole packet will be captured on all the MACs.
							 1,				// promiscuous mode (nonzero means promiscuous)
							 100,			// read timeout
							 errbuf			// error buffer
							 )) == NULL)
	{
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
}


int pcap_main()
{
	
	/* Check the link layer. We support only Ethernet for simplicity. */
	if(pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr,"\nThis program works only on Ethernet networks.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	if(d->addresses != NULL)
		/* Retrieve the mask of the first address of the interface */
		netmask=((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* If the interface is without addresses we suppose to be in a C class network */
		netmask=0xffffff; 


	//compile the filter
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) <0 )
	{
		fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	//set the filter
	if (pcap_setfilter(adhandle, &fcode)<0)
	{
		fprintf(stderr,"\nError setting the filter.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	printf("\nlistening on %s...\n", d->description);
	
	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);
	
	/* start the capture */
	pcap_loop(adhandle, 0, packet_handler, NULL);
	
	return 0;
}

struct netif net_test;

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct tm *ltime;
	char timestr[16];
	ip_header *ih;
	udp_header *uh;
	u_int ip_len;
	u_short sport,dport;
	time_t local_tv_sec;
	int i;
	int notown = 0;

	/*
	 * unused parameter
	 */
	(VOID)(param);

	/* convert the timestamp to readable format */
	local_tv_sec = header->ts.tv_sec;
	ltime=localtime(&local_tv_sec);
	strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);

	/* print timestamp and length of the packet */
	printf("%s.%.6d len:%d ", timestr, header->ts.tv_usec, header->len);

	/* retireve the position of the ip header */
	ih = (ip_header *) (pkt_data +
		14); //length of ethernet header

	/* retireve the position of the udp header */
	ip_len = (ih->ver_ihl & 0xf) * 4;
	uh = (udp_header *) ((u_char*)ih + ip_len);

	/* convert from network byte order to host byte order */
	sport = ntohs( uh->sport );
	dport = ntohs( uh->dport );

	/* print ip addresses and udp ports */
	printf("%d.%d.%d.%d.%d -> %d.%d.%d.%d.%d\n",
		ih->saddr.byte1,
		ih->saddr.byte2,
		ih->saddr.byte3,
		ih->saddr.byte4,
		sport,
		ih->daddr.byte1,
		ih->daddr.byte2,
		ih->daddr.byte3,
		ih->daddr.byte4,
		dport);
	for( i = 0; i < header->len; i++ ){
		printf( "%.2X ", pkt_data[i] );
		if ( (i % 16) == 15) printf("\n");
	}
	printf( "\n\n");

	for( i = 0; i < 6; i++ ){
		if( pkt_data[i+6] != net_test.hwaddr[i]){
			notown = 1;
			break;
		}
	}
	if( notown ){
		input_pkts(&net_test, pkt_data, header->len);
	}


}


int main(int argc, char** argv)
{
  ip4_addr_t addr;
  ip4_addr_t netmask;
  ip4_addr_t gw;
  size_t len;

  pcap_init();

  lwip_init();

  IP4_ADDR(&addr, 192, 168, 11, 100);
  IP4_ADDR(&netmask, 255, 255, 255, 0);
  IP4_ADDR(&gw, 192, 168, 11, 1);

  netif_add(&net_test, &addr, &netmask, &gw, &net_test, testif_init, ethernet_input);
  netif_set_up(&net_test);
  netif_set_link_up(&net_test);

#if LWIP_IPV6
  nd6_tmr(); /* tick nd to join multicast groups */
#endif
  dns_setserver(0, &net_test.gw);

  /* initialize apps */
  httpd_init();
  //lwiperf_start_tcp_server_default(NULL, NULL);
  //mdns_resp_init();
  //mdns_resp_add_netif(&net_test, "lwIPhostname.local", 255);
  //snmp_init();
  //netbiosns_init();

  pcap_main();

  return 0;
}
