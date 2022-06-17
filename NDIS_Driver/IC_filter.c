//#ifndef _ICC_
//#define _ICC_
#include <ndis.h>
#include <filteruser.h>
#include<ntddk.h>

#define	ETHER_ADDR_LEN		6
#define IPV4_LENGTH 0x4 //ipv4长度
#define IPV6_LENGTH 0x10 //ipv6长度
#define TYPE_IPV4  0x0008 //ipv4协议类型
#define TYPE_IPV6  0xdd86 //ipv6协议类型
#define PROTOCOL_UDP 0x11 //UDP协议类型
#define PROTOCOL_TCP 0x6  //TCP协议类型

#define NEW_FC_CODE CTL_CODE(FILE_DEVICE_UNKNOWN,0x999,METHOD_BUFFERED,FILE_READ_ACCESS)//增加规则
#define DEL_FC_CODE CTL_CODE(FILE_DEVICE_UNKNOWN,0x99a,METHOD_BUFFERED,FILE_READ_ACCESS)//删除规则
#define START_FC_CODE CTL_CODE(FILE_DEVICE_UNKNOWN,0x99b,METHOD_BUFFERED,FILE_READ_ACCESS)//开启
#define STOP_FC_CODE CTL_CODE(FILE_DEVICE_UNKNOWN,0x99c,METHOD_BUFFERED,FILE_READ_ACCESS)//停止
#define EXIT_FC_CODE CTL_CODE(FILE_DEVICE_UNKNOWN,0x99d,METHOD_BUFFERED,FILE_READ_ACCESS)//卸载
#define DEL_ALL_FC_CODE CTL_CODE(FILE_DEVICE_UNKNOWN,0x99e,METHOD_BUFFERED,FILE_READ_ACCESS)//删除所有规则
#define GET_B_FC_CODE CTL_CODE(FILE_DEVICE_UNKNOWN,0x99f,METHOD_NEITHER,FILE_ANY_ACCESS)//获取恶意会话列表
#define GET_B_NUM_CODE CTL_CODE(FILE_DEVICE_UNKNOWN,0x9a0,METHOD_NEITHER,FILE_ANY_ACCESS)//获取恶意会话数目
typedef PUCHAR PPacket;

//--------------------------------------------锁相关-----------------------------------------------------------------------------------------------------------------------------------------
//第一个锁锁的是IO对过滤规则的增删
//第二个锁锁的是对温和的会话的增加
//第三个锁锁的是对恶意的会话的增加
KSPIN_LOCK IC_LOCK, IC_LOCK2, IC_LOCK3;
KIRQL IC_IRQL, IC_IRQL2, IC_IRQL3;

//-------------------------------------------开启过滤功能----------------------------------------------------------------------------------------------------------------------------------------

int start_flag = 0;//是否开启过滤功能，1开启，0关闭



//-------------------------------协议栈用的结构------------------------------------------------------------------------------------------------------------------------------------------------
//路局链路层
typedef struct	ether_header {
	UCHAR	ether_dhost[ETHER_ADDR_LEN];
	UCHAR	ether_shost[ETHER_ADDR_LEN];
	USHORT	ether_type;
}TP_ETHERNET, *PTP_ETHERNET;

//网络层类型
typedef struct ipv4 {
	PUCHAR Src_add;//源IP
	PUCHAR Dst_add;//目的IP
	PUCHAR Protocol;//上层协议
	ULONG Length;//ip头长度

}IP_V4,* PIP_V4;

typedef struct ipv6 {
	PUCHAR Src_add;//源IP
	PUCHAR Dst_add;//目的IP
	PUCHAR Protocol;//上层协议
	ULONG Length;//ip头长度
}IP_V6, *PIP_V6;

typedef union network_layer
{
	//这里可以增加类型
	IP_V4 ipv4;
	IP_V6 ipv6;

}Network_Layer;

//传输层类型
//UDP 结构 其中 二字节以上需要 大端序转小端序才是正确值
typedef struct udp_header
{
	USHORT srcport;   // 源端口
	USHORT dstport;   // 目的端口
	USHORT total_len; // 包括UDP报头及UDP数据的长度(单位:字节)
	USHORT chksum;    // 校验和
}TP_UDP, * PTP_UDP;
//TCP 结构 其中 二字节以上需要 大端序转小端序才是正确值
typedef struct tp_tcp {
	unsigned short src_port;    //源端口号
	unsigned short dst_port;    //目的端口号
	unsigned int   seq_no;      //序列号
	unsigned int   ack_no;      //确认号

	unsigned char reserved_1 : 4; //保留6位中的4位首部长度
	unsigned char thl : 4;    //tcp头部长度
	unsigned char flag : 6;  //6位标志
	unsigned char reseverd_2 : 2; //保留6位中的2位

	unsigned short wnd_size;   //16位窗口大小
	unsigned short chk_sum;    //16位TCP检验和
	unsigned short urgt_p;     //16为紧急指针
}TP_TCP, * PTP_TCP;
//可添加类型结构
typedef union transport_layer
{
	//这里可以增加类型
	PTP_TCP tcp;
	PTP_UDP udp;

}Transport_Layer;

//-----------------------------拦截相关结构-----------------------------------------------------------------------------------------------------------------------------------------------

//存在驱动的包基本信息，用于过滤
typedef struct packet_information {
	//此结构可随着功能的增加自定义

	UCHAR V4_Or_V6;//是过滤ipv4还是ipv6  0:ipv4  1:ipv6
	union src_ip
	{
		PUCHAR ipv4;
		PUCHAR ipv6;
	}SRC_IP;
	union dst_ip
	{
		PUCHAR ipv4;
		PUCHAR ipv6;
	}DST_IP;
	USHORT src_port; //2字节小于8字节用值
	USHORT dst_port;
}Packet_Information, * PPacket_Information;
//读取的过滤规则（RING 3 传入）
typedef struct filter_condition {
	//此结构可随着功能的增加自定义，和驱动的相同结构一起改

	UCHAR S_Or_R;//在发送时过滤还是收到时过滤 0：发送 ，1：收到
	UCHAR S_Or_D;//是过滤源还是目的 0：源，1：目的
	UCHAR V4_Or_V6;//是过滤ipv4还是ipv6  0:ipv4  1:ipv6
	union
	{
		UCHAR ipv4[4];
		UCHAR ipv6[16];
	}IP;
	USHORT port;
	int flag;//标识号，删除时要用
	struct filter_condition* prior;
	struct filter_condition* next;
	//UCHAR flag[20];//对应使用的过滤函数：1使用，0不使用，预留20个过滤规则函数的位置
}Filter_Condition, * PFilter_Condition;
//过滤规则链表
typedef struct fc_list {
	PFilter_Condition head;//链表第一个
	PFilter_Condition last;//链表最后一个
	int num;
}FC_List;

FC_List FC_list = { 0 };//这个需要全局变量，过滤规则链表

//一个包数据流的第一个包的临时信息，用于过滤对比
//--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//记录所有会话，仅记录对方的ip
typedef struct record {
	UCHAR v4_or_v6;
	union 
	{
		UCHAR ipv4[4];
		UCHAR ipv6[16];
	}IP;
	struct record* next;
}Record,*PRecord;

typedef struct record_list {
	PRecord head;
	PRecord last;
	int num;
}Rocord_List,*PRocord_List;
//benign rocord list
Rocord_List B_Rrd_List = { 0 };
//malware rocord list
Rocord_List M_Rrd_List = { 0 };

//--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

//Network_Layer是否为空，当该网络层未定义时，返回空

int Network_Layer_Is_Space(Network_Layer LS) {
	PUCHAR AD = (PUCHAR)&LS;
	for (int i = 0; i < sizeof(Network_Layer); i++)
	{
		if (AD[i] != 0x00)
		{
			return 0;
		}
	}
	return 1;
}
//Network_Layer是否为空，当该传输层未定义时，返回空
int Transport_Layer_Is_Space(Transport_Layer LS) {
	PUCHAR AD = (PUCHAR)&LS;
	for (int i = 0; i < sizeof(Transport_Layer); i++)
	{
		if (AD[i] != 0x00)
		{
			return 0;
		}
	}
	return 1;
}

//----------------------------------协议栈相关-----------------------------------------------------------------------------------------------------------------------------
//通过NET_BUFFER获取一个网络封包数据,此PPacket需要释放，（组包函数）
PPacket IC_Get_Packer(PNET_BUFFER nb) {
	PMDL Mdl = nb->CurrentMdl;//取当前
	ULONG packet_size = nb->DataLength;//此包的大小
	PPacket packet = (PPacket)ExAllocatePool(NonPagedPool, packet_size);//申请存放的空间
	//失败
	if (packet == NULL)
	{
		DbgPrint("packet分配内存失败\n");
		return NULL;
	}
	PPacket packetoffset = packet;
	ULONG offset = nb->CurrentMdlOffset;//偏移
	ULONG i = 0;
	do {
		ULONG cinnum = 0;
		PUCHAR OEP;
		ULONG thisMDLsize = Mdl->ByteCount;
		if (i == 0 && packet_size > (thisMDLsize - offset))//不存在offset>thismdlsize的情况
		{
			//第一个MDL，且此MDL装不下完整的包的时候
			cinnum = thisMDLsize - offset;
			OEP = (PUCHAR)Mdl->MappedSystemVa + offset;
			i++;
		}
		else if (i == 0)
		{
			//第一个MDL，此MDL可以装下一个完整的包
			cinnum = packet_size;
			OEP = (PUCHAR)Mdl->MappedSystemVa + offset;
		}
		else {
			//读第二个、第三个、。。MDL的数据
			cinnum = thisMDLsize;
			OEP = (PUCHAR)Mdl->MappedSystemVa;
		}
		//cinnum = Mdl->ByteCount;
		memcpy(packetoffset, OEP, cinnum);
		packetoffset += cinnum;
		Mdl = Mdl->Next;
	} while (Mdl != NULL);//最后填满packet，即为包的数据
	return packet;
}
//返回数据链路层部分数据
PTP_ETHERNET IC_Get_Data_Link_Layer(PPacket packet)
{
	PTP_ETHERNET LS =  (PTP_ETHERNET)packet;
	/*if (packet == NULL)
		return LS;*/
	return LS;
}
//返回网络层部分数据
Network_Layer IC_Get_Network_Layer(PPacket packet, PTP_ETHERNET data_link, PPacket_Information LSPI)
{
	Network_Layer LLS = { 0 };
	switch (data_link->ether_type)
	{
	case TYPE_IPV4:
	{
		IP_V4 LS;
		LS.Src_add = packet + 26;//源IP
		LS.Dst_add = packet + 30;//目的IP
		LS.Protocol = packet + 23;//上层协议类型
		UCHAR LENG;
		memcpy(&LENG, packet + 14, 0x1);
		LENG &= 0x0f;
		ULONG L = 0;
		memcpy(&L, &LENG, 1);
		LS.Length = L * 0x4;
		LLS.ipv4 = LS;

	
		LSPI->V4_Or_V6 = 0;
		LSPI->SRC_IP.ipv4 = LS.Src_add;
		LSPI->DST_IP.ipv4 = LS.Dst_add;

		


		return LLS;
	}
	case TYPE_IPV6:
	{
		IP_V6 LS;
		LS.Length = 40;//ipv6头固定40字节
		LS.Protocol = packet + 20;//上层协议类型
		LS.Src_add = packet + 22;//源IP
		LS.Dst_add = packet + 26 + 16;//目的IP
		LLS.ipv6 = LS;


		LSPI->V4_Or_V6 = 1;
		LSPI->SRC_IP.ipv6 = LS.Src_add;
		LSPI->DST_IP.ipv6 = LS.Dst_add;

		
		return LLS;
	}
	default:
		return LLS;
		break;
	}


}
//返回传输层部分数据
Transport_Layer IC_Get_Transport_Layer(PPacket packet, PTP_ETHERNET data_link, Network_Layer network_data, PPacket_Information LSPI) {
	Transport_Layer LLS = { 0 };
	PUCHAR lpacket = packet;
	lpacket += 14;//跳过数据链路层
	if (Network_Layer_Is_Space(network_data))//是否为未定义的网络层
		return LLS;
	switch (data_link->ether_type)//不同的网络层协议，要加上的偏移不同
	{
	case TYPE_IPV4://确定是ipv4协议
	{
		lpacket += network_data.ipv4.Length;//跳过网络层
		switch (*network_data.ipv4.Protocol)
		{
		case PROTOCOL_TCP:
		{
			LLS.tcp = (PTP_TCP)lpacket;

			LSPI->src_port = LLS.tcp->src_port;
			LSPI->dst_port = LLS.tcp->dst_port;


			break;
		}
		case PROTOCOL_UDP:
		{
			LLS.udp = (PTP_UDP)lpacket;

			LSPI->src_port = LLS.udp->srcport;
			LSPI->dst_port = LLS.udp->dstport;


			break;
		}
		default://未定义的传输层，返回空
			break;
		}

		break;
	}
	case TYPE_IPV6://确定是ipv6协议
	{
		lpacket += network_data.ipv6.Length;//跳过网络层
		switch (*network_data.ipv6.Protocol)
		{
		case PROTOCOL_TCP:
		{
			LLS.tcp = (PTP_TCP)lpacket;

			LSPI->src_port = LLS.tcp->src_port;
			LSPI->dst_port = LLS.tcp->dst_port;


			break;
		}
		case PROTOCOL_UDP:
		{
			LLS.udp = (PTP_UDP)lpacket;

			LSPI->src_port = LLS.udp->srcport;
			LSPI->dst_port = LLS.udp->dstport;


			break;
		}
		default://未定义的传输层，返回空
			break;
		}
		break;
	}
	default://未定义的网络层，返回空
		break;
	}


	return LLS;
}

//----------------------------------拦截相关----------------------------------------------------------------------------------------------------------------------------
//调试专用CALL
void TEST(PNET_BUFFER_LIST pnbl) {
	PNET_BUFFER pnb = NET_BUFFER_LIST_FIRST_NB(pnbl);
	/*if (pnb->Next == NULL)
		return;*/
	Packet_Information LSPI = { 0 };//获取此包的临时信息
	PPacket packet = IC_Get_Packer(pnb);
	PTP_ETHERNET PET = IC_Get_Data_Link_Layer(packet);
	Network_Layer NL = IC_Get_Network_Layer(packet, PET,&LSPI);
	Transport_Layer TL = IC_Get_Transport_Layer(packet, PET, NL,&LSPI);
	DbgBreakPoint();
	ExFreePool(packet);
}
//发送时过滤函数，返回0表时放过，返回1表时拦截
int Send_Filtering_Function(IN PNET_BUFFER_LIST pnbl,OUT PPacket* Need_Free,IN OUT PPacket_Information LSPI) {
	if (FC_list.num == 0)//判断是否存在规则
		return 0;
	//Packet_Information LSPI = { 0 };//获取此包的临时信息
	//DbgBreakPoint();
	PNET_BUFFER pnb = NET_BUFFER_LIST_FIRST_NB(pnbl);

	PPacket packet = IC_Get_Packer(pnb);
	if (packet == NULL)
		return 0;
	*Need_Free = packet;
	PTP_ETHERNET PET = IC_Get_Data_Link_Layer(packet);
	Network_Layer NL = IC_Get_Network_Layer(packet, PET,LSPI);
	Transport_Layer TL = IC_Get_Transport_Layer(packet, PET, NL,LSPI);
	int bj = 0;//bj=1:此包符合过滤规则中的ip地址，下一步需要判断端口号是否符合
	PFilter_Condition FCLS = NULL;
	if (LSPI->DST_IP.ipv4 == NULL || LSPI->SRC_IP.ipv4 == NULL )
		return 0;//网络层不是ip协议，不管
	for (FCLS = FC_list.head; FCLS != NULL; FCLS = FCLS->next)
	{
		if (FCLS->S_Or_R == 1)
			continue;//说明这个规则不归我管,取下一个规则

		//if (FCLS->S_Or_R == 2)//进程端口过滤 
		//{
		//	PUCHAR PP1 = (PUCHAR) & (FCLS->port) + 1;
		//	PUCHAR PP2 = (PUCHAR) & (LSPI->src_port);
		//	if (*PP1 == *PP2)
		//		if (*(PP1 - 1) == *(PP2 + 1))
		//			return 1;//说明端口满足规则
		//}
		switch (FCLS->S_Or_D) {
		case 0://过滤源
		{
			//过滤ip，bj=1说明ip符号，下一步需要判断端口
			switch (FCLS->V4_Or_V6)
			{
			case 0://IPV4
			{
				int i = 0;
				for (i = 0; i < IPV4_LENGTH; i++)
					if (FCLS->IP.ipv4[i] != LSPI->SRC_IP.ipv4[i])
						break;//不匹配
				if (i < IPV4_LENGTH)
					continue;//不匹配
				bj = 1;//说明这个包ip匹配，下一步验证端口是否匹配
				break;

			}
			case 1://IPV6
			{
				int i = 0;
				for (i = 0; i < IPV6_LENGTH; i++)
					if (FCLS->IP.ipv6[i] != LSPI->SRC_IP.ipv6[i])
						break;
				if (i < IPV6_LENGTH)
					continue;//不匹配
				bj = 1;
				break;//说明这个包匹配需要拦截
			}
			default: // 理论不存在这种情况
				return 0;
			}
			//过滤端口(这里不能直接对比USHORT型，因为端序不一样)
			if (bj = 1 && FCLS->port == 0)
				return 1;//过滤这个ip的所有端口
			if (bj = 1 && FCLS->port != 0 && LSPI->src_port !=0x00)
			{
				PUCHAR PP1 = (PUCHAR) & (FCLS->port) + 1;
				PUCHAR PP2 = (PUCHAR) & (LSPI->src_port);
				if (*PP1 == *PP2)
					if (*(PP1 - 1) == *(PP2 + 1))
						return 1;//说明端口满足规则
			}
			bj = 0;

			continue;
		}
		case 1://过滤目的
		{
			//过滤ip
			switch (FCLS->V4_Or_V6)
			{
			case 0://IPV4
			{
				int i = 0;
				for (i = 0; i < IPV4_LENGTH; i++)
					if (FCLS->IP.ipv4[i] != LSPI->DST_IP.ipv4[i])
						break;
				if (i < IPV4_LENGTH)
					continue;//不匹配
				bj = 1;
				break;

			}
			case 1://IPV6
			{
				int i = 0;
				for (i = 0; i < IPV6_LENGTH; i++)
					if (FCLS->IP.ipv6[i] != LSPI->DST_IP.ipv6[i])
						break;
				if (i < IPV6_LENGTH)
					continue;//不匹配
				bj = 1;//说明这个包匹配需要拦截
				break;
			}
			default: // 理论不存在这种情况,但是可扩展其他网络层协议
				return 0;
			}
			//过滤端口
			if (bj = 1 && FCLS->port == 0)
				return 1;//过滤这个ip的所有端口
			if (bj = 1 && FCLS->port != 0 && LSPI->dst_port != 0x00)
			{
				PUCHAR PP1 = (PUCHAR) & (FCLS->port) + 1;
				PUCHAR PP2 = (PUCHAR) & (LSPI->dst_port);
				if (*PP1 == *PP2)
					if (*(PP1 - 1) == *(PP2 + 1))
						return 1;//说明端口满足规则
			}
			bj = 0;
			continue;
		}
		default://进程过滤 
			if (bj == 0 && LSPI->src_port != 0 && FCLS->port != 0)
			{
				PUCHAR PP1 = (PUCHAR) & (FCLS->port) + 1;
				PUCHAR PP2 = (PUCHAR) & (LSPI->src_port);//在拦截发送时，本机进程端口一定是属于源端口
				if (*PP1 == *PP2)
					if (*(PP1 - 1) == *(PP2 + 1))
						return 1;//说明端口满足规则
			}
			continue;
		}
	}


	return 0;



}
//接收时过滤函数，返回0表时放过，返回1表时拦截
int Rec_Filtering_Function(IN PNET_BUFFER_LIST pnbl,OUT PPacket* Need_Free,IN OUT PPacket_Information RLSPI) {
	if (FC_list.num == 0)//判断是否存在规则
		return 0;
	//Packet_Information RLSPI = { 0 };
	PNET_BUFFER pnb = NET_BUFFER_LIST_FIRST_NB(pnbl);
	/*if (pnb->Next == NULL)
		return;*/
	PPacket packet = IC_Get_Packer(pnb);
	if (packet == NULL)
		return 0;
	*Need_Free = packet;
	PTP_ETHERNET PET = IC_Get_Data_Link_Layer(packet);
	Network_Layer NL = IC_Get_Network_Layer(packet, PET,RLSPI);
	Transport_Layer TL = IC_Get_Transport_Layer(packet, PET, NL, RLSPI);
	int bj = 0;
	PFilter_Condition FCLS = NULL;
	if (RLSPI->DST_IP.ipv4 == NULL || RLSPI->SRC_IP.ipv4 == NULL )
		return 0;//网络层不是ip协议，不管
	for (FCLS = FC_list.head; FCLS != NULL; FCLS = FCLS->next)
	{
		if (FCLS->S_Or_R == 0)
			continue;//说明这个规则不归我管,取下一个规则

		//if (FCLS->S_Or_R == 2)//进程端口过滤 
		//{
		//	PUCHAR PP1 = (PUCHAR) & (FCLS->port) + 1;
		//	PUCHAR PP2 = (PUCHAR) & (RLSPI->dst_port);//对收到的包来说，目的端口就是我们本机进程端口
		//	if (*PP1 == *PP2)
		//		if (*(PP1 - 1) == *(PP2 + 1))
		//			return 1;//说明端口满足规则
		//}
		switch (FCLS->S_Or_D) {
		case 0://过滤源
		{
			//过滤ip，bj=1说明ip符号，下一步需要判断端口
			switch (FCLS->V4_Or_V6)
			{
			case 0://IPV4
			{
				int i = 0;
				for (i = 0; i < IPV4_LENGTH; i++)
					if (FCLS->IP.ipv4[i] != RLSPI->SRC_IP.ipv4[i])
						break;
				if (i < IPV4_LENGTH)
					continue;//不匹配
				bj = 1;//说明这个包ip匹配，下一步验证端口是否匹配
				break;

			}
			case 1://IPV6
			{
				int i = 0;
				for (i = 0; i < IPV6_LENGTH; i++)
					if (FCLS->IP.ipv6[i] != *(RLSPI->SRC_IP.ipv6 + i))
						break;
				if (i < IPV6_LENGTH)
					continue;//不匹配
				bj = 1;
				break;//说明这个包匹配需要拦截
			}
			default: // 理论不存在这种情况
				return 0;
			}
			//过滤端口(这里不能直接对比USHORT型，因为端序不一样)
			if (bj = 1 && FCLS->port == 0)
				return 1;//过滤这个ip的所有端口
			if (bj = 1 && FCLS->port != 0 && RLSPI->src_port != 0)
			{
				PUCHAR PP1 = (PUCHAR) & (FCLS->port) + 1;
				PUCHAR PP2 = (PUCHAR) & (RLSPI->src_port);
				if (*PP1 == *PP2)
					if (*(PP1 - 1) == *(PP2 + 1))
						return 1;//说明端口满足规则
			}
			bj = 0;

			continue;
		}
		case 1://过滤目的
		{
			//过滤ip
			switch (FCLS->V4_Or_V6)
			{
			case 0://IPV4
			{
				int i = 0;
				for (i = 0; i < IPV4_LENGTH; i++)
					if (FCLS->IP.ipv4[i] != RLSPI->DST_IP.ipv4[i])
						break;
				if (i < IPV4_LENGTH)
					continue;//不匹配
				bj = 1;
				break;

			}
			case 1://IPV6
			{
				int i = 0;
				for (i = 0; i < IPV6_LENGTH; i++)
					if (FCLS->IP.ipv6[i] != RLSPI->DST_IP.ipv6[i])
						break;
				if (i < IPV6_LENGTH)
					continue;//不匹配
				bj = 1;//说明这个包匹配需要拦截
				break;
			}
			default: // 理论不存在这种情况
				return 0;
			}
			//过滤端口
			if (bj = 1 && FCLS->port == 0)
				return 1;//过滤这个ip的所有端口
			if (bj = 1 && FCLS->port != 0 && RLSPI->dst_port != 0)
			{
				PUCHAR PP1 = (PUCHAR) & (FCLS->port) + 1;
				PUCHAR PP2 = (PUCHAR) & (RLSPI->dst_port);
				if (*PP1 == *PP2)
					if (*(PP1 - 1) == *(PP2 + 1))
						return 1;//说明端口满足规则
			}
			bj = 0;
			continue;
		}
		default://进程过滤 
			if (bj == 0 && FCLS->port != 0 && RLSPI->dst_port != 0)//收包时拦截，进程端口一定是目的端口
			{
				//DbgBreakPoint();
				PUCHAR PP1 = ((PUCHAR) & (FCLS->port)) + 1;
				PUCHAR PP2 = (PUCHAR) & (RLSPI->dst_port);
				if (*PP1 == *PP2)
					if (*(PP1 - 1) == *(PP2 + 1))
						return 1;//说明端口满足规则
			}
			continue;
		}
	}


	return 0;



}

//----------------------------------会话相关----------------------------------------------------------------------------------------------------------------------------
//清空温和会话列表
VOID Clear_B_Rrd_List()
{
	PRecord free = B_Rrd_List.head;
	PRecord next_free = NULL;
	KeAcquireSpinLock(&IC_LOCK2, &IC_IRQL2);//上锁
	B_Rrd_List.num = 0;
	B_Rrd_List.head = B_Rrd_List.last = NULL;
	KeReleaseSpinLock(&IC_LOCK2, IC_IRQL2);//解锁
	for (; free != NULL; free = next_free)
	{
		next_free = free->next;
		ExFreePool(free);
	}
}
//清空恶意会话列表
VOID Clear_M_Rrd_List()
{
	PRecord free = M_Rrd_List.head;
	PRecord next_free = NULL;
	KeAcquireSpinLock(&IC_LOCK3, &IC_IRQL3);//上锁
	M_Rrd_List.num = 0;
	M_Rrd_List.head = M_Rrd_List.last = NULL;
	KeReleaseSpinLock(&IC_LOCK3, IC_IRQL3);//解锁
	for (; free != NULL; free = next_free)
	{
		next_free = free->next;
		ExFreePool(free);
	}
}

//增加恶意会话
int M_NEW_Record(PPacket_Information RLSPI) {
	
	PRecord PNew_record = ExAllocatePool(NonPagedPool, sizeof(Record));
	if (PNew_record == NULL)
	{
		DbgBreakPoint();
		return 0;
	}
	memset(PNew_record, 0, sizeof(Record));
	PNew_record->v4_or_v6 = RLSPI->V4_Or_V6;
	//DbgBreakPoint();
	switch (RLSPI->V4_Or_V6)
	{
	case 0:
	{
		for (int i = 0; i < IPV4_LENGTH; i++)
			PNew_record->IP.ipv4[i] = RLSPI->SRC_IP.ipv4[i];//记录ip
	}
	case 1:
	{
		for (int i = 0; i < IPV6_LENGTH; i++)
			PNew_record->IP.ipv6[i] = RLSPI->SRC_IP.ipv6[i]; //记录ip
	}
	default:
		break;
	}
	KeAcquireSpinLock(&IC_LOCK3, &IC_IRQL3);//上锁
	if (M_Rrd_List.last != NULL)
	{
		M_Rrd_List.last->next = PNew_record;
		M_Rrd_List.last = PNew_record;
	}
	else
		M_Rrd_List.head = M_Rrd_List.last = PNew_record;
	M_Rrd_List.num++;
	KeReleaseSpinLock(&IC_LOCK3, IC_IRQL3);//解锁
	return 1;
}
//记录会话（收包）
int Rec_Record_IP(PPacket_Information RLSPI) {
	if (RLSPI->DST_IP.ipv4 ==NULL )
		return 0;
	PRecord LS = NULL;
	//判断是否已在 温和会话列表
	for (LS = B_Rrd_List.head; LS != NULL; LS = LS->next)
	{
		if (LS->v4_or_v6 != RLSPI->V4_Or_V6)
			continue;
		switch (RLSPI->V4_Or_V6)
		{
		case 0:
		{
			int i = 0;
			for (i = 0; i < IPV4_LENGTH; i++)
				if (LS->IP.ipv4[i] != RLSPI->SRC_IP.ipv4[i])
					break;//不匹配
			if (i == IPV4_LENGTH)
				return 0;
			break;
		}
		case 1:
		{
			int i = 0;
			for (i = 0; i < IPV6_LENGTH; i++)
				if (LS->IP.ipv6[i] != RLSPI->SRC_IP.ipv6[i])
					break;//不匹配
			if (i == IPV6_LENGTH)
				return 0;
			break;
		}
		default:
			break;
		
		}
	}
	//判断是否已在 恶意会话列表
	for (LS =  M_Rrd_List.head; LS != NULL; LS = LS->next)
	{
		if (LS->v4_or_v6 != RLSPI->V4_Or_V6)
			continue;
		switch (RLSPI->V4_Or_V6)
		{
		case 0:
		{
			int i = 0;
			for (i = 0; i < IPV4_LENGTH; i++)
				if (LS->IP.ipv4[i] != RLSPI->SRC_IP.ipv4[i])
					break;//不匹配
			if (i == IPV4_LENGTH)
				return 0;
			break;
		}
		case 1:
		{
			int i = 0;
			for (i = 0; i < IPV6_LENGTH; i++)
				if (LS->IP.ipv6[i] != RLSPI->SRC_IP.ipv6[i])
					break;//不匹配
			if (i == IPV6_LENGTH)
				return 0;
			break;
		}
		default:
			break;

		}
	}
	M_NEW_Record(RLSPI);
	return 1;
}
//记录温和会话
int B_New_Record(PPacket_Information LSPI)
{
	
	PRecord PNew_record = ExAllocatePool(NonPagedPool, sizeof(Record));
	if (PNew_record == NULL)
	{
		DbgBreakPoint();
		return 0;
	}
	memset(PNew_record, 0, sizeof(Record));
	PNew_record->v4_or_v6 = LSPI->V4_Or_V6;
	//DbgBreakPoint();
	switch (LSPI->V4_Or_V6)
	{
	case 0:
	{
		for (int i = 0; i < IPV4_LENGTH; i++)
			PNew_record->IP.ipv4[i] = LSPI->DST_IP.ipv4[i]; 
	}
	case 1:
	{
		for (int i = 0; i < IPV6_LENGTH; i++)
			PNew_record->IP.ipv6[i] = LSPI->DST_IP.ipv4[i];
	}
	default:
		break;
	}
	KeAcquireSpinLock(&IC_LOCK2, &IC_IRQL2);//上锁
	if (B_Rrd_List.last != NULL)
	{
		B_Rrd_List.last->next= PNew_record;
		B_Rrd_List.last = PNew_record;
	}
	else
		B_Rrd_List.head = B_Rrd_List.last = PNew_record;
	B_Rrd_List.num++;
	KeReleaseSpinLock(&IC_LOCK2, IC_IRQL2);//解锁
	return 1;
	
}
//记录会话（发包）
int Send_Record_IP(PPacket_Information LSPI) {
	if (LSPI->DST_IP.ipv4 == NULL)
		return 0;
	PRecord LS = NULL;
	//判断是否已在 温和会话列表
	for (LS = B_Rrd_List.head; LS != NULL; LS = LS->next)
	{
		if (LS->v4_or_v6 != LSPI->V4_Or_V6)
			continue;
		switch (LSPI->V4_Or_V6)
		{
		case 0:
		{
			int i = 0;
			for (i = 0; i < IPV4_LENGTH; i++)
				if (LS->IP.ipv4[i] != LSPI->DST_IP.ipv4[i])
					break;//不匹配
			if (i == IPV4_LENGTH)
				return 0;
			break;
		}
		case 1:
		{
			int i = 0;
			for (i = 0; i < IPV6_LENGTH; i++)
				if (LS->IP.ipv6[i] != LSPI->DST_IP.ipv6[i])
					break;//不匹配
			if (i == IPV6_LENGTH)
				return 0;
			break;
		}
		default:
			break;

		}
	}
	//判断是否已在 恶意会话列表
	for (LS = M_Rrd_List.head; LS != NULL; LS = LS->next)
	{
		if (LS->v4_or_v6 != LSPI->V4_Or_V6)
			continue;
		switch (LSPI->V4_Or_V6)
		{
		case 0:
		{
			int i = 0;
			for (i = 0; i < IPV4_LENGTH; i++)
				if (LS->IP.ipv4[i] != LSPI->DST_IP.ipv4[i])
					break;//不匹配
			if (i == IPV4_LENGTH)
				return 0;
			break;
		}
		case 1:
		{
			int i = 0;
			for (i = 0; i < IPV6_LENGTH; i++)
				if (LS->IP.ipv4[i] != LSPI->DST_IP.ipv4[i])
					break;//不匹配
			if (i == IPV6_LENGTH)
				return 0;
			break;
		}
		default:
			break;

		}
	}
	if (B_Rrd_List.num > 100)//温和记录只记录100条，然后重新计数
		Clear_B_Rrd_List();
	B_New_Record(LSPI);
	return 1;
}





//#endif