#ifndef _PROCDATA_H
#define _PROCDATA_H

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#include "datastruct.h"
#include <memory.h>
#include <stdio.h>
#include <WinSock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>

struct iph_pack procIpHeader(char *ipdata);

// udp,tcp,icmp �� http,ftp... ���Ǳ���װ��ip���ݰ���
void procUdpPack(char *ipdata);
void procTcpPack(char *ipdata);
void procIcmpPack(char *ipdata);
void procIgmpPack(char *ipdata);


#endif