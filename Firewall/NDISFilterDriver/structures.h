#ifndef STRUCTURES
#define STRUCTURES


#define IOCTL_FROM_MANAGER CTL_CODE(0x00008000,0x801,METHOD_BUFFERED,FILE_ANY_ACCESS)

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

typedef struct _RULE_IPV4
{
	ULONG Id;
	UCHAR Begin[4];
	UCHAR End[4];
	PVOID Next;
} RULE_IPV4, *PRULE_IPV4;

typedef struct _RULE_IPV6
{
	ULONG Id;
	UCHAR Begin[16];
	UCHAR End[16];
	PVOID Next;
} RULE_IPV6, *PRULE_IPV6;

typedef struct _RULE_ETH
{
	ULONG Id;
	UCHAR Addr[6];
} RULE_ETH, *PRULE_ETH;
#endif