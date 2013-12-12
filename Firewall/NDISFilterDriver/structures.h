#ifndef STRUCTURES
#define STRUCTURES

#define ETHERTYPE_IP4 0x0800
#define ETHERTYPE_ARP 0x0806
#define ETHERTYPE_IP6 0x86DD

typedef struct _NDF_ETH_HEADER
{
	UCHAR Dst[6];
	UCHAR Src[6];
	USHORT Type;
} NDF_ETH_HEADER, *PNDF_ETH_HEADER;

typedef struct _NDF_IPV4_HEADER
{
	ULONG HeaderInfo[2];
	UCHAR TTL : 8;
	UCHAR Protocol : 8;
	USHORT HeaderChecksum : 16;
	UCHAR SrcIp[4];
	UCHAR DstIp[4];
} NDF_IPV4_HEADER, *PNDF_IPV4_HEADER;

typedef struct _NDF_TCP_HEADER
{
	USHORT SrcPort : 16;
	USHORT DstPort : 16;
	ULONG SequenceNumber : 32;
	ULONG ApprovalNumber : 32;
	ULONG HeaderInfo[2];
} NDF_TCP_HEADER, *PNDF_TCP_HEADER;

typedef struct _NDF_IPV6_HEADER
{
	ULONG HeaderInfo[2];
	UCHAR SrcAddress[16];
	UCHAR DstAddress[16];
} NDF_IPV6_HEADER, *PNDF_IPV6_HEADER;

typedef struct _NDF_ARP_HEADER
{
	ULONG HeaderInfo[2];
	UCHAR SrcMac[6];
	UCHAR SrcIp[4];
	UCHAR DstMac[6];
	UCHAR DstIp[4];
} NDF_ARP_HEADER, *PNDF_ARP_HEADER;

#endif