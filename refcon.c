/*
    RefCon - DPlus Reflector Connector
    Copyright (C) 2019 Doug McLain

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include <stdio.h> 
#include <stdlib.h>
#include <signal.h>
#include <unistd.h> 
#include <string.h> 
#include <netdb.h>
#include <ctype.h>
#include <signal.h>
#include <sys/types.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <netinet/in.h>
#include <sys/ioctl.h>

#define BUFSIZE 2048
#define DEBUG_SEND
#define DEBUG_RECV

char 		*ref1;
char 		*ref2;
int 		udp1;
int 		udp2;
fd_set 		udpset; 
struct 		sockaddr_in host1;
struct 		sockaddr_in host2;
uint8_t 	buf[BUFSIZE];
uint32_t 	host1_cnt;
uint32_t 	host2_cnt;
uint8_t 	host1_connect;
uint8_t 	host2_connect;

const uint16_t CCITT16_TABLE1[] = {
	0x0000U, 0x1189U, 0x2312U, 0x329bU, 0x4624U, 0x57adU, 0x6536U, 0x74bfU,
	0x8c48U, 0x9dc1U, 0xaf5aU, 0xbed3U, 0xca6cU, 0xdbe5U, 0xe97eU, 0xf8f7U,
	0x1081U, 0x0108U, 0x3393U, 0x221aU, 0x56a5U, 0x472cU, 0x75b7U, 0x643eU,
	0x9cc9U, 0x8d40U, 0xbfdbU, 0xae52U, 0xdaedU, 0xcb64U, 0xf9ffU, 0xe876U,
	0x2102U, 0x308bU, 0x0210U, 0x1399U, 0x6726U, 0x76afU, 0x4434U, 0x55bdU,
	0xad4aU, 0xbcc3U, 0x8e58U, 0x9fd1U, 0xeb6eU, 0xfae7U, 0xc87cU, 0xd9f5U,
	0x3183U, 0x200aU, 0x1291U, 0x0318U, 0x77a7U, 0x662eU, 0x54b5U, 0x453cU,
	0xbdcbU, 0xac42U, 0x9ed9U, 0x8f50U, 0xfbefU, 0xea66U, 0xd8fdU, 0xc974U,
	0x4204U, 0x538dU, 0x6116U, 0x709fU, 0x0420U, 0x15a9U, 0x2732U, 0x36bbU,
	0xce4cU, 0xdfc5U, 0xed5eU, 0xfcd7U, 0x8868U, 0x99e1U, 0xab7aU, 0xbaf3U,
	0x5285U, 0x430cU, 0x7197U, 0x601eU, 0x14a1U, 0x0528U, 0x37b3U, 0x263aU,
	0xdecdU, 0xcf44U, 0xfddfU, 0xec56U, 0x98e9U, 0x8960U, 0xbbfbU, 0xaa72U,
	0x6306U, 0x728fU, 0x4014U, 0x519dU, 0x2522U, 0x34abU, 0x0630U, 0x17b9U,
	0xef4eU, 0xfec7U, 0xcc5cU, 0xddd5U, 0xa96aU, 0xb8e3U, 0x8a78U, 0x9bf1U,
	0x7387U, 0x620eU, 0x5095U, 0x411cU, 0x35a3U, 0x242aU, 0x16b1U, 0x0738U,
	0xffcfU, 0xee46U, 0xdcddU, 0xcd54U, 0xb9ebU, 0xa862U, 0x9af9U, 0x8b70U,
	0x8408U, 0x9581U, 0xa71aU, 0xb693U, 0xc22cU, 0xd3a5U, 0xe13eU, 0xf0b7U,
	0x0840U, 0x19c9U, 0x2b52U, 0x3adbU, 0x4e64U, 0x5fedU, 0x6d76U, 0x7cffU,
	0x9489U, 0x8500U, 0xb79bU, 0xa612U, 0xd2adU, 0xc324U, 0xf1bfU, 0xe036U,
	0x18c1U, 0x0948U, 0x3bd3U, 0x2a5aU, 0x5ee5U, 0x4f6cU, 0x7df7U, 0x6c7eU,
	0xa50aU, 0xb483U, 0x8618U, 0x9791U, 0xe32eU, 0xf2a7U, 0xc03cU, 0xd1b5U,
	0x2942U, 0x38cbU, 0x0a50U, 0x1bd9U, 0x6f66U, 0x7eefU, 0x4c74U, 0x5dfdU,
	0xb58bU, 0xa402U, 0x9699U, 0x8710U, 0xf3afU, 0xe226U, 0xd0bdU, 0xc134U,
	0x39c3U, 0x284aU, 0x1ad1U, 0x0b58U, 0x7fe7U, 0x6e6eU, 0x5cf5U, 0x4d7cU,
	0xc60cU, 0xd785U, 0xe51eU, 0xf497U, 0x8028U, 0x91a1U, 0xa33aU, 0xb2b3U,
	0x4a44U, 0x5bcdU, 0x6956U, 0x78dfU, 0x0c60U, 0x1de9U, 0x2f72U, 0x3efbU,
	0xd68dU, 0xc704U, 0xf59fU, 0xe416U, 0x90a9U, 0x8120U, 0xb3bbU, 0xa232U,
	0x5ac5U, 0x4b4cU, 0x79d7U, 0x685eU, 0x1ce1U, 0x0d68U, 0x3ff3U, 0x2e7aU,
	0xe70eU, 0xf687U, 0xc41cU, 0xd595U, 0xa12aU, 0xb0a3U, 0x8238U, 0x93b1U,
	0x6b46U, 0x7acfU, 0x4854U, 0x59ddU, 0x2d62U, 0x3cebU, 0x0e70U, 0x1ff9U,
	0xf78fU, 0xe606U, 0xd49dU, 0xc514U, 0xb1abU, 0xa022U, 0x92b9U, 0x8330U,
	0x7bc7U, 0x6a4eU, 0x58d5U, 0x495cU, 0x3de3U, 0x2c6aU, 0x1ef1U, 0x0f78U };


int max(int x, int y) 
{ 
    if (x > y) 
        return x; 
    else
        return y; 
} 

void process_signal(int sig)
{
	static uint32_t c1 = 0;
	static uint32_t c2 = 0;
	if(sig == SIGINT){
		fprintf(stderr, "\n\nShutting down link\n");
		buf[0] = 0x05;
		buf[1] = 0x00;
		buf[2] = 0x18;
		buf[3] = 0x00;
		buf[4] = 0x00;
		sendto(udp1, buf, 5, 0, (const struct sockaddr *)&host1, sizeof(host1));
		sendto(udp2, buf, 5, 0, (const struct sockaddr *)&host2, sizeof(host2));
		close(udp1);
		close(udp2);
		exit(EXIT_SUCCESS);
	}
	if(sig == SIGALRM){
		if(c1 != host1_cnt){
		c1 = host1_cnt;
		}
		else{
			c1 = host1_cnt = 0;
			host1_connect = 1;
			fprintf(stderr, "%s ping timeout\n", ref1);
		}
		if(c2 != host2_cnt){
			c2 = host2_cnt;
		}
		else{
			c2 = host2_cnt = 0;
			host2_connect = 1;
			fprintf(stderr, "%s ping timeout\n", ref2);
		}
		alarm(5);
	}
}

void addCCITT161(unsigned char *in, unsigned int length)
{
	
	union C{
		uint16_t crc16;
		uint8_t  crc8[2U];
	} c;


	c.crc16 = 0xFFFFU;

	for (unsigned int i = 0U; i < (length - 2U); i++)
		c.crc16 = (c.crc8[1U]) ^ CCITT16_TABLE1[c.crc8[0U] ^ in[i]];

	c.crc16 = ~(c.crc16);

	in[length - 2U] = c.crc8[0U];
	in[length - 1U] = c.crc8[1U];
}

int main(int argc, char **argv)
{
	struct sockaddr_in rx;
	struct hostent *hp;
	char *mod1;
	char *mod2;
	char *host1_url;
	char *host2_url;
	int host1_port;
	int host2_port;
	char callsign[6U];
	socklen_t l = sizeof(host1);
	int rxlen;
	int r;
	int udprx,maxudp;
	uint16_t streamid = 0;
	const uint8_t header[5] = {0x80,0x44,0x53,0x56,0x54}; 	//DVSI packet header

	if(argc != 4){
		fprintf(stderr, "Usage: refcon [CALLSIGN] [REFName1:MOD1:REFHost1IP:PORT] [REFName2:MOD2:REFHost2IP:PORT]\n");
		return 0;
	}
	else{
		memset(callsign, ' ', 6);
		memcpy(callsign, argv[1], strlen(argv[1]));
		
		ref1 = strtok(argv[2], ":");
		mod1 = strtok(NULL, ":");
		host1_url = strtok(NULL, ":");
		host1_port = atoi(strtok(NULL, ":"));
		
		ref2= strtok(argv[3], ":");
		mod2 = strtok(NULL, ":");
		host2_url = strtok(NULL, ":");
		host2_port = atoi(strtok(NULL, ":"));
		
		printf("REF1: %s%c %s:%d\n", ref1, mod1[0], host1_url, host1_port);
		printf("REF2: %s%c %s:%d\n", ref2, mod2[0], host2_url, host2_port);
	}
	
	signal(SIGINT, process_signal); 						//Handle CTRL-C gracefully
	signal(SIGALRM, process_signal); 						//Watchdog
	
	if ((udp1 = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("cannot create socket\n");
		return 0;
	}
	if ((udp2 = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("cannot create socket\n");
		return 0;
	}
	
	maxudp = max(udp1, udp2) + 1;
	
	memset((char *)&host1, 0, sizeof(host1));
	host1.sin_family = AF_INET;
	host1.sin_port = htons(host1_port);

	memset((char *)&host2, 0, sizeof(host2));
	host2.sin_family = AF_INET;
	host2.sin_port = htons(host2_port);

	hp = gethostbyname(host1_url);
	if (!hp) {
		fprintf(stderr, "could not resolve %s\n", host1_url);
		return 0;
	}
	memcpy((void *)&host1.sin_addr, hp->h_addr_list[0], hp->h_length);
	
	hp = gethostbyname(host2_url);
	if (!hp) {
		fprintf(stderr, "could not resolve %s\n", host2_url);
		return 0;
	}
	memcpy((void *)&host2.sin_addr, hp->h_addr_list[0], hp->h_length);
	host1_cnt = 0;
	host2_cnt = 0;
	host1_connect = 1;
	host2_connect = 1;
	alarm(5);

	while (1) {
		if(host1_connect){
			host1_connect = 0;
			buf[0] = 0x05;
			buf[1] = 0x00;
			buf[2] = 0x18;
			buf[3] = 0x00;
			buf[4] = 0x01;
			sendto(udp1, buf, 5, 0, (const struct sockaddr *)&host1, sizeof(host1));
			fprintf(stderr, "Connecting to %s...\n", ref1);
		}
		if(host2_connect){
			host2_connect = 0;
			buf[0] = 0x05;
			buf[1] = 0x00;
			buf[2] = 0x18;
			buf[3] = 0x00;
			buf[4] = 0x01;
			sendto(udp2, buf, 5, 0, (const struct sockaddr *)&host2, sizeof(host2));
			fprintf(stderr, "Connecting to %s...\n", ref2);
		}
		FD_ZERO(&udpset);
		FD_SET(udp1, &udpset);
		FD_SET(udp2, &udpset);
		r = select(maxudp, &udpset, NULL, NULL, NULL);
		//fprintf(stderr, "Select returned r == %d\n", r);
		rxlen = 0;
		if(r > 0){
			if(FD_ISSET(udp1, &udpset)) {
				rxlen = recvfrom(udp1, buf, BUFSIZE, 0, (struct sockaddr *)&rx, &l);
				udprx = udp1;
			}
			if(FD_ISSET(udp2, &udpset)) {
				rxlen = recvfrom(udp2, buf, BUFSIZE, 0, (struct sockaddr *)&rx, &l);
				udprx = udp2;
			}
		}
#ifdef DEBUG_RECV
		if(rxlen){
			if(rx.sin_addr.s_addr == host1.sin_addr.s_addr){
			fprintf(stderr, "RECV %s: ", ref1);
			}
			else if(rx.sin_addr.s_addr == host2.sin_addr.s_addr){
				fprintf(stderr, "RECV %s: ", ref2);
			}
			for(int i = 0; i < rxlen; ++i){
				fprintf(stderr, "%02x ", buf[i]);
			}
			fprintf(stderr, "\n");
			fflush(stderr);
		}
#endif
		if((rxlen == 5) && (buf[4] == 0x01)){
			int x = (rand() % (999999 - 7245 + 1)) + 7245;
			char serial[9];
			sprintf(serial, "HS%06d", x);
			buf[0] = 0x1c;
			buf[1] = 0xc0;
			buf[2] = 0x04;
			buf[3] = 0x00;
			memcpy(&buf[4], callsign, 6);
			memset(&buf[10], 0, 10);
			memcpy(&buf[20], serial, 8);
			sendto(udprx, buf, 28, 0, (const struct sockaddr *)&rx, sizeof(rx));
#ifdef DEBUG_SEND
			if(rx.sin_addr.s_addr == host1.sin_addr.s_addr){
				fprintf(stderr, "SEND %s: ", ref1);
			}
			else if(rx.sin_addr.s_addr == host2.sin_addr.s_addr){
				fprintf(stderr, "SEND %s: ", ref2);
			}
			for(int i = 0; i < 28; ++i){
				fprintf(stderr, "%02x ", buf[i]);
			}
			fprintf(stderr, "\n");
			fflush(stderr);
#endif
		}
		if(rxlen == 3){
			sendto(udprx, buf, 3, 0, (const struct sockaddr *)&rx, sizeof(rx));

			if(rx.sin_addr.s_addr == host1.sin_addr.s_addr){
				//fprintf(stderr, "SEND %s: ", REF1);
				++host1_cnt;
			}
			else if(rx.sin_addr.s_addr == host2.sin_addr.s_addr){
				//fprintf(stderr, "SEND %s: ", REF2);
				++host2_cnt;
			}
/*
			for(int i = 0; i < 3; ++i){
				fprintf(stderr, "%02x ", buf[i]);
			}
			fprintf(stderr, "\n");
			fflush(stderr);
*/
		}
		if((rxlen == 0x3a) && (!memcmp(&buf[1], header, 5))) {
			for(int i = 0; i < 4; ++i){
				if((buf[0x34+i] > 0x20) && (buf[0x34+i] < 0x30)){
					buf[0x34+i] = 0x20;
				}
				else if((buf[0x34+i] > 0x39) && (buf[0x34+i] < 0x41)){
					buf[0x34+i] = 0x20;
				}
				else if((buf[0x34+i] > 0x5a) && (buf[0x34+i] < 0x61)){
					buf[0x34+i] = 0x20;
				}
				else if(buf[0x34+i] > 0x7a) {
					buf[0x34+i] = 0x20;
				}
			}
			
			if( (udprx == udp1) && (rx.sin_addr.s_addr == host1.sin_addr.s_addr) && !memcmp(&buf[0x14], ref1, 6) && (buf[0x1b] == mod1[0]) ){
				memcpy(&buf[20], ref2, 6);
				buf[26] = ' ';
				buf[27] = mod2[0];
				streamid = (buf[14] << 8) | (buf[15] & 0xff);
				addCCITT161(&buf[17], 41);
				sendto(udp2, buf, 0x3a, 0, (const struct sockaddr *)&host2, sizeof(host2));
#ifdef DEBUG_SEND
				fprintf(stderr, "SEND %s: ", ref2);
				for(int i = 0; i < 0x3a; ++i){
					fprintf(stderr, "%02x ", buf[i]);
				}
				fprintf(stderr, "\n");
				fflush(stderr);
#endif
			}
			else if( (udprx == udp1) && (rx.sin_addr.s_addr == host1.sin_addr.s_addr) && !memcmp(&buf[0x1c], ref1, 6) && (buf[0x23] == mod1[0]) ){
				memcpy(&buf[20], ref2, 6);
				buf[26] = ' ';
				buf[27] = mod2[0];
				streamid = (buf[14] << 8) | (buf[15] & 0xff);
				addCCITT161(&buf[17], 41);
				sendto(udp2, buf, 0x3a, 0, (const struct sockaddr *)&host2, sizeof(host2));
#ifdef DEBUG_SEND
				fprintf(stderr, "SEND %s: ", ref2);
				for(int i = 0; i < 0x3a; ++i){
					fprintf(stderr, "%02x ", buf[i]);
				}
				fprintf(stderr, "\n");
				fflush(stderr);
#endif
			}
			else if( (udprx == udp2) && (rx.sin_addr.s_addr == host2.sin_addr.s_addr) && !memcmp(&buf[0x14], ref2, 6) && (buf[0x1b] == mod2[0]) ){
				memcpy(&buf[20], ref1, 6);
				buf[26] = ' ';
				buf[27] = mod1[0];
				streamid = (buf[14] << 8) | (buf[15] & 0xff);
				addCCITT161(&buf[17], 41);
				sendto(udp1, buf, 0x3a, 0, (const struct sockaddr *)&host1, sizeof(host1));
#ifdef DEBUG_SEND
				fprintf(stderr, "SEND %s: ", ref1);
				for(int i = 0; i < 0x3a; ++i){
					fprintf(stderr, "%02x ", buf[i]);
				}
				fprintf(stderr, "\n");
				fflush(stderr);
#endif
			}
		}
		if(rxlen == 0x1d){
			uint16_t s = (buf[14] << 8) | (buf[15] & 0xff);
			if(s == streamid){
				if( (udprx == udp1) && (rx.sin_addr.s_addr == host1.sin_addr.s_addr) ){
					sendto(udp2, buf, 0x1d, 0, (const struct sockaddr *)&host2, sizeof(host2));
#ifdef DEBUG_SEND
					fprintf(stderr, "SEND %s: ", ref2);
					for(int i = 0; i < 0x1d; ++i){
						fprintf(stderr, "%02x ", buf[i]);
					}
					fprintf(stderr, "\n");
					fflush(stderr);
#endif
				}
				else if( (udprx == udp2) && (rx.sin_addr.s_addr == host2.sin_addr.s_addr) ){
					sendto(udp1, buf, 0x1d, 0, (const struct sockaddr *)&host1, sizeof(host1));
#ifdef DEBUG_SEND
					fprintf(stderr, "SEND %s: ", ref1);
					for(int i = 0; i < 0x1d; ++i){
						fprintf(stderr, "%02x ", buf[i]);
					}
					fprintf(stderr, "\n");
					fflush(stderr);
#endif
				}
			}
		}
	}
}
