

#include "procdata.h"
// 处理ip首部
struct iph_pack procIpHeader(char *ipdata)
{
	struct iph_pack len;
	memset(&len, 0, sizeof(len));
	if (!ipdata)
		return len;
	struct ip_header *iph = (struct ip_header *)ipdata;
	len.hlen = (iph->ver4_hlen4 & 0xf) * 4;
	//printf("header len : %d ", len.hlen);
	len.tlen = iph->tlen;
	len.souraddr = iph->souraddr;
	len.destaddr = iph->destaddr;

	return len;
}

void procUdpPack(char *ipdata)
{
	struct iph_pack hPack = procIpHeader(ipdata);
	// 随便找一个变量作判断
	if (hPack.hlen == 0)
		return;

	struct udp_header *uh = (struct udp_header *)(ipdata + hPack.hlen);
	struct in_addr addr1,addr2;
	printf("total_len(%-4d)\t", ntohs(hPack.tlen));
	char buf[16];
	memset(buf, 0, 16);
	switch (ntohs(uh->destport))
	{
		// DNS
	case 53:
		strncpy(buf, "DNS", 3);
		break;

		// TFTP
	case 69:
		strncpy(buf, "TFTP", 4);
		break;

		// SNMP
	case 161:
		strncpy(buf, "SNMP", 4);
		break;

	case 520:
		strncpy(buf, "RIP", 3);
		break;

		// 非常用的熟知端口号
	default:
		strncpy(buf, "UDP", 3);
		break;
	}
	printf("%-6s\t", buf);
	addr1.s_addr = hPack.souraddr;
	addr2.s_addr = hPack.destaddr;
	printf("%-15s:%5d  ->  ",
		inet_ntoa(addr1), ntohs(uh->sourport)
		);
	printf("%-15s:%5d\n", inet_ntoa(addr2), ntohs(uh->destport));
}

void procTcpPack(char *ipdata)
{
	struct iph_pack hPack = procIpHeader(ipdata);
	// 随便找一个变量作判断
	if (hPack.hlen == 0)
		return;

	struct tcp_header *th = (struct tcp_header *)(ipdata + hPack.hlen);
	struct in_addr addr1, addr2;
	printf("total_len(%-4d)\t", ntohs(hPack.tlen));
	char buf[16];
	memset(buf, 0, 16);
	switch (ntohs(th->destport))
	{
		// FTP
	case 21:
		strncpy(buf, "FTP", 3);
		break;

		// TELNET
	case 23:
		strncpy(buf, "TELNET", 6);
		break;

		// SMTP
	case 161:
		strncpy(buf, "SMTP", 4);
		break;

		// HTTP
	case 80:
		strncpy(buf, "HTTP", 4);
		break;

		// 非常用的熟知端口号
	default:
		strncpy(buf, "TCP", 3);
		break;
	}
	printf("%-6s\t", buf);
	addr1.s_addr = hPack.souraddr;
	addr2.s_addr = hPack.destaddr;
	printf("%-15s:%5d  ->  ",
		inet_ntoa(addr1), ntohs(th->sourport)
		);
	printf("%-15s:%5d\n", inet_ntoa(addr2), ntohs(th->destport));
}

void procIcmpPack(char *ipdata)
{
	struct iph_pack hPack = procIpHeader(ipdata);
	struct in_addr addr1, addr2;
	char buf[16] = "ICMP";

	printf("total_len(%-4d)\t%-6s\t%-22s ->  ", 
		ntohs(hPack.tlen),
		buf,
		inet_ntoa((addr1.s_addr = hPack.souraddr, addr1))
		);
	printf("%-22s\n", inet_ntoa((addr2.s_addr = hPack.destaddr, addr2)));
	
}