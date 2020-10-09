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
//#define DEBUG_SEND
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
