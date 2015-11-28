// NetSniffer.cpp : 定义控制台应用程序的入口点。
//
/*
简单说明一下什么是网络嗅探器，网络嗅探器是一个抓取所有经过网卡数据的软件，在一般使用电脑时，网卡
只接受到发送至本机的数据，那是因为这是网卡是非混杂模式的，挡一个目的地址非本机地址的数据包经过网
卡时，网卡在数据链路层（mac地址）检测到是非本机数据，则直接丢弃，当设置为混杂模式时，所有经过网卡
的数据包均可被读取出来。
*/
#include "stdafx.h"

#include <WinSock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>

#include "datastruct.h"
#include "procdata.h"

#pragma comment(lib, "Ws2_32.lib")

#define BUF 256
#define RECVBUF 1500

int _tmain(int argc, _TCHAR* argv[])
{
	// Declare some variables
	WSADATA wsaData;
	int iResult = 0;
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != NO_ERROR) {
		wprintf(L"Error at WSAStartup()\n");
		return 1;
	}

	SOCKET sock = INVALID_SOCKET;
	// 理论上在socket 第三个参数设定为制定协议类型（如0x0800或0x0806或多个等等），则可以获取
	// 数据链路层的数据，即包括了以太网帧的首部在数据部分，但window 封闭了这一层，所以获取
	// 数据只能去到ip层。若想获取以太网帧可以使用winpcap 开发库，linux下是libpcap。（注意：
	// Linux下可用socket套接字获取数据链路层）
	if ((sock = socket(AF_INET, SOCK_RAW, /*htons(0x0800)*/IPPROTO_IP)) == INVALID_SOCKET)
	{
		printf("socket error:%d\n", GetLastError());
		WSACleanup();
		return 1;
	}

	// hostent 结构体包含了所有能抓取到的网卡对应的地址
	struct sockaddr_in addr;
	char hostname[BUF] = {0};
	int namelen = gethostname(hostname, BUF);
	struct hostent *phost = gethostbyname(hostname);
	if (phost != NULL)
	{
		addr.sin_family = AF_INET;
		addr.sin_port = htons(0);
		char *paddr;
		int i = 0;
		for (paddr = *phost->h_addr_list; paddr != NULL; ++i, paddr = *(phost->h_addr_list + i))
		{
			memcpy(&(addr.sin_addr), paddr, phost->h_length);
			printf("[%d] %s\n", i, inet_ntoa(addr.sin_addr));
		}
		printf("Please chose a device for Sniffer:");
		int index;
		reenter:
		scanf("%d", &index);
		if (index < 0 || index >= i)
			goto reenter;
		paddr = *(phost->h_addr_list + index);
		memcpy(&(addr.sin_addr), paddr, phost->h_length);
	}
	else
	{
		closesocket(sock);
		WSACleanup();
		return 1;
	}

	if (bind(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) == SOCKET_ERROR)
	{
		closesocket(sock);
		WSACleanup();
		return 1;
	}
	
	// 设置网卡为混杂模式
	unsigned long flag = 1;
	if (ioctlsocket(sock, SIO_RCVALL, &flag) != 0)
	{
		closesocket(sock);
		WSACleanup();
		return 1;
	}

	char recvbuf[RECVBUF];
	size_t size = 0;
	pip_header pip;
	
	int count = 0;
	while (1)
	{	// 接受到IP数据包
		size = recv(sock, recvbuf, RECVBUF, 0);
		if (size == 0 || size == SOCKET_ERROR)
		{
			if (size == SOCKET_ERROR)
			{
				closesocket(sock);
				WSACleanup();
				return 1;
			}
			continue;
		}
		count++;
		//
		printf("[%0.4d]\t", count);
		pip = (pip_header)recvbuf;
		switch (pip->proto)
		{
		case IPPROTO_TCP:
			procTcpPack(recvbuf);
			break;
		case IPPROTO_UDP:
			procUdpPack(recvbuf);
			break;
		case IPPROTO_ICMP:
			procIcmpPack(recvbuf);
			break;
		case IPPROTO_IGMP:
			printf("Catch a IGMP, len : %d.\n", ntohs(pip->tlen));
			break;
		case IPPROTO_EGP:
			printf("Catch a EGP, len : %d.\n", ntohs(pip->tlen));
			break;
		case IPPROTO_IGP:
			printf("Catch a IGP, len : %d.\n", ntohs(pip->tlen));
			break;
		case IPPROTO_ESP:
			printf("Catch a ESP, len : %d.\n", ntohs(pip->tlen));
			break;
		case MIB_IPPROTO_OSPF:
			printf("Catch a OSPF, len : %d.\n", ntohs(pip->tlen));
			break;
			
		default:
			printf("Unknow proto.\n");
			break;
		};
		memset(recvbuf, 0, sizeof(recvbuf));
	}
	return 0;
}

