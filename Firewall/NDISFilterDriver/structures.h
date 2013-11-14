#ifndef STRUCTURES
#define STRUCTURES

#define ETHERTYPE_IP 0x0800

typedef struct _NDF_ETH_HEADER
{
	UCHAR Dst[6];
	UCHAR Src[6];
	USHORT Type;
} NDF_ETH_HEADER, *PNDF_ETH_HEADER;

typedef struct _NDF_IPV4_HEADER
{
	UCHAR Version : 4;
	UCHAR IHL : 4;
	UCHAR DSCP : 6;
	UCHAR ECN : 2;
	USHORT TotalLength : 16;
	USHORT Id : 16;
	UCHAR Flags : 3;
	USHORT FragmentOffset : 13;
	UCHAR TTL : 8;
	UCHAR Protocol : 8;
	USHORT HeaderChecksum : 16;
	ULONG SrcIp : 32;
	ULONG DstIp : 32;
} NDF_IPV4_HEADER, *PNDF_IPV4_HEADER;

typedef struct _NDF_TCP_HEADER
{
	USHORT SrcPort : 16;
	USHORT DstPort : 16;
	ULONG SequenceNumber : 32;
	ULONG ApprovalNumber : 32;
	UCHAR DataOffset : 4;
	UCHAR Reserved : 6;
	UCHAR Flags : 6;
	USHORT WindowSize : 16 ;
	USHORT Checksum : 16;
	USHORT UrgentPointer : 16;
} NDF_TCP_HEADER, *PNDF_TCP_HEADER;

#endif