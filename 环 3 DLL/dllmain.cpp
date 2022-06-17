// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"

#define CTL_CODE( DeviceType, Function, Method, Access ) (                 \
    ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method) \
)
#define FILE_DEVICE_UNKNOWN             0x00000022
#define METHOD_BUFFERED                 0
#define FILE_READ_ACCESS          ( 0x0001 )    // file & pipe
#define METHOD_NEITHER                  3
#define FILE_ANY_ACCESS                 0



#define NEW_FC_CODE CTL_CODE(FILE_DEVICE_UNKNOWN,0x999,METHOD_BUFFERED,FILE_READ_ACCESS)//增加条件
#define DEL_FC_CODE CTL_CODE(FILE_DEVICE_UNKNOWN,0x99a,METHOD_BUFFERED,FILE_READ_ACCESS)//删除条件
#define START_FC_CODE CTL_CODE(FILE_DEVICE_UNKNOWN,0x99b,METHOD_BUFFERED,FILE_READ_ACCESS)//开启
#define STOP_FC_CODE CTL_CODE(FILE_DEVICE_UNKNOWN,0x99c,METHOD_BUFFERED,FILE_READ_ACCESS)//停止
#define DEL_ALL_FC_CODE CTL_CODE(FILE_DEVICE_UNKNOWN,0x99e,METHOD_BUFFERED,FILE_READ_ACCESS)//删除所有规则
#define GET_B_FC_CODE CTL_CODE(FILE_DEVICE_UNKNOWN,0x99f,METHOD_NEITHER,FILE_ANY_ACCESS)//获取恶意会话
#define GET_B_NUM_CODE CTL_CODE(FILE_DEVICE_UNKNOWN,0x9a0,METHOD_NEITHER,FILE_ANY_ACCESS)//获取恶意会话数目

#define DEVICE_NAME L"\\\\.\\NDISLWF" //符号链接名
HANDLE mydevice = NULL;
PVOID M_IP = 0;//从驱动获取的恶意结构空间地址
int m_ip_get_num = -1;//配合get_next_m_ip使用，按顺序获取恶意ip
int all_m_ip_num = -1;//全部恶意ip的个数

//添加ipv4过滤规则，输入规则标识号，ip，端口，在发送时还是接收时拦截，此ip的源ip还是目的ip
int WINAPI ipv4_new_rule(int flag,int ip[],  int _port,int S_Or_R,int S_Or_D)
{
    /*if (_1 < 0 || _1>255 || _2 < 0 || _2>255 || _3 < 0 || _3>255 || _4 < 0 || _4>255 || _port < 0 || _port>65535)
        return 0;*/
    for (int i = 0; i < 4; i++)
        if (ip[i] < 0 || ip[0]>255)
            return 0;
    if (_port < 0 || _port>65535)
        return 0;
    //errno_t err = fopen_s(&pf, "CONTEXT.IC", "a+b");
    Filter_Condition Task = {0};
    Task.S_Or_R = (UCHAR)S_Or_R;
    Task.S_Or_D = (UCHAR)S_Or_D;
    Task.V4_Or_V6 = 0;
    /*Task.IP.ipv4[0] = (UCHAR)_1;
    Task.IP.ipv4[1] = (UCHAR)_2;
    Task.IP.ipv4[2] = (UCHAR)_3;
    Task.IP.ipv4[3] = (UCHAR)_4;*/
    for (int i = 0; i < 4; i++)
        Task.IP.ipv4[i] = ip[i];
    Task.port = (USHORT)_port;

    Task.flag = flag;

    DWORD lenth = 0;
    //stop();
    DeviceIoControl(mydevice, NEW_FC_CODE, NULL, 0, &Task, sizeof(Task), &lenth, NULL);
    
    //start();
    //fwrite(&Task, sizeof(Filter_Condition), 1, pf);
    //fclose(pf);
    if ((int)lenth == 1)
        return 1;
    return 0;
    
}
//添加ipv6过滤规则，输入规则标识号，ip，端口，在发送时还是接收时拦截，此ip的源ip还是目的ip
int WINAPI ipv6_new_rule(int flag, int ip[], int _port, int S_Or_R, int S_Or_D)
{
    for (int i = 0; i < 16; i++)
        if (ip[i] < 0 || ip[0]>255)
            return 0;
    if (_port < 0 || _port>65535)
        return 0;
    Filter_Condition Task = { 0 };
    Task.S_Or_R = (UCHAR)S_Or_R;
    Task.S_Or_D = (UCHAR)S_Or_D;
    Task.V4_Or_V6 = 1;
    for (int i = 0; i < 16; i++)
        Task.IP.ipv6[i] = ip[i];
    Task.port = (USHORT)_port;

    Task.flag = flag;

    DWORD lenth = 0;
    //stop();
    DeviceIoControl(mydevice, NEW_FC_CODE, NULL, 0, &Task, sizeof(Task), &lenth, NULL);
    if ((int)lenth == 1)
        return 1;
    return 0;
}
//开启过滤
int WINAPI start() {
    DWORD lenth = 0;
    DeviceIoControl(mydevice, START_FC_CODE, NULL, 0, NULL, 0, &lenth, NULL);
    if ((int)lenth == 1)
        return 1;
    return 0;
}
//停止过滤
int WINAPI stop() {
    DWORD lenth = 0;
    DeviceIoControl(mydevice, STOP_FC_CODE, NULL, 0, NULL, 0, &lenth, NULL);
    if ((int)lenth == 1)
        return 1;
    return 0;
}
//删除规则，输入此规则的标识号
int WINAPI dele(int flag) {
    DWORD lenth = 0;
    DeviceIoControl(mydevice, DEL_FC_CODE, NULL, 0, &flag, sizeof(int), &lenth, NULL);
    if ((int)lenth == 1)
        return 1;
    return 0;
}
//通过进程拦截，输入规则标识号，进程PID，在发送时还是接收时拦截
int WINAPI process_new_rule(int flag,int PID,int S_Or_R) {
    PMIB_TCPTABLE_OWNER_PID pTcpTable = NULL;
    PMIB_UDPTABLE_OWNER_PID pUdpTable = NULL;
    DWORD dwSize;
    //TCP
    pTcpTable = (PMIB_TCPTABLE_OWNER_PID)malloc(sizeof(MIB_TCPTABLE_OWNER_PID));
    if (pTcpTable == NULL) {
        return 0;
    }
    dwSize = sizeof(MIB_TCPTABLE_OWNER_PID);
    if ((GetExtendedTcpTable(pTcpTable, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)) == ERROR_INSUFFICIENT_BUFFER)
    {
        free(pTcpTable);
        pTcpTable = (PMIB_TCPTABLE_OWNER_PID)malloc(sizeof(MIB_TCPTABLE_OWNER_PID));
        if (pTcpTable == NULL)
        {
            return 0;
        }
    }
    if ((GetExtendedTcpTable(pTcpTable, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)) == NO_ERROR)
    {
        for (int i = 0; i <(int)pTcpTable->dwNumEntries; i++)
        {
            if (pTcpTable->table[i].dwOwningPid == PID)
            {
                int port_s = 0;//原先是大端序，要转换成小端序
                char* p = (char*)&port_s;
                char* k = (char*)&pTcpTable->table[i].dwLocalPort;
                *(p + 1) = *k;
                *(p) = *(k + 1);
                Filter_Condition Task = { 0 };
                Task.port = (USHORT)port_s;
                Task.S_Or_D = 2;
                Task.S_Or_R = S_Or_R;
                Task.flag = flag;
                DWORD lenth;
                DeviceIoControl(mydevice, NEW_FC_CODE, NULL, 0, &Task, sizeof(Task), &lenth, NULL);
                Sleep(100);
                continue;
            }
        }
    }
    else
    {
        free(pTcpTable);
        return 0;
    }
    free(pTcpTable);
    //UDP
    pUdpTable = (PMIB_UDPTABLE_OWNER_PID)malloc(sizeof(MIB_UDPTABLE_OWNER_PID));
    if (pUdpTable == NULL) {
        return 0;
    }
    dwSize = sizeof(MIB_UDPTABLE_OWNER_PID);
    if ((GetExtendedUdpTable(pUdpTable, &dwSize, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0)) == ERROR_INSUFFICIENT_BUFFER)
    {
        free(pUdpTable);
        pUdpTable = (PMIB_UDPTABLE_OWNER_PID)malloc(dwSize);
        if (pUdpTable == NULL)
        {
            return 0;
        }
    }
    if ((GetExtendedUdpTable(pUdpTable, &dwSize, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0)) == NO_ERROR)
    {
        for (int i = 0; i < (int)pUdpTable->dwNumEntries; i++)
        {
            if (pUdpTable->table[i].dwOwningPid == PID)
            {
                int port_s = 0;
                char* p = (char*)&port_s;
                char* k = (char*)&pUdpTable->table[i].dwLocalPort;
                *(p + 1) = *k;
                *(p) = *(k + 1);
                Filter_Condition Task = { 0 };
                Task.port = (USHORT)port_s;
                Task.S_Or_D = 2;
                Task.S_Or_R = S_Or_R;
                Task.flag = flag;
                DWORD lenth;
                DeviceIoControl(mydevice, NEW_FC_CODE, NULL, 0, &Task, sizeof(Task), &lenth, NULL);
                Sleep(100);
                continue;
            }
        }
    }
    else
    {
        free(pUdpTable);
        return 0;
    }
    free(pUdpTable);
    return 1;



}
//删除所有规则
int WINAPI dele_all() {
    DWORD lenth = 0;
    DeviceIoControl(mydevice, DEL_ALL_FC_CODE, NULL, 0, NULL, 0, &lenth, NULL);
    if ((int)lenth == 1)
        return 1;
    return 0;
}
//获取恶意ip的数量
int WINAPI get_m_ip_num() {
    DWORD lent = 0;
    int k = 0;
    DeviceIoControl(mydevice,GET_B_NUM_CODE, &k, 4, NULL, NULL, &lent, NULL);
    if ((int)lent == 1)
        return k;
    return -1;
}
//获取下一个恶意ip
int WINAPI get_next_m_ip(OUT int* out)
{
    for (int i=0; i < 16; i++)
        *(out + i) = 0;
    if (all_m_ip_num < 1 || m_ip_get_num >= all_m_ip_num)
        return 0;//没有,或已经取完
    int j = 4;//ipv4长度
    PRecord LS = (PRecord)M_IP;
    LS += m_ip_get_num;
    if (LS->v4_or_v6 == 0x1)
        j = 16;//ipv6长度
    PBYTE int_ip = NULL;
    for (int i = 0; i < j; i++)
    {
        int_ip = (PBYTE)(out + i);
        *int_ip = LS->IP.ipv6[i];
    }
    if (LS->v4_or_v6 == 0x0)
    {
        *(out + 4) = -1;//设一个分隔符-1，读到第5个位置为-1就知道这个是ipv4
    }
    m_ip_get_num++;//下一次就取下一个
    return 1;
}
//获取第一个恶意ip
int WINAPI get_first_m_ip(OUT int *out) {
    //PRecord AD = (PRecord)malloc(sizeof(Record)*lenth);
    all_m_ip_num = get_m_ip_num();
    if (all_m_ip_num == -1)
        return 0;//失败
    DWORD lent = 0;
    if (M_IP != NULL)
        free(M_IP);
    M_IP = malloc(sizeof(Record) * all_m_ip_num);
    m_ip_get_num = 0;//第一个
    DeviceIoControl(mydevice, GET_B_FC_CODE, M_IP, sizeof(Record) * all_m_ip_num, NULL, NULL, &lent, NULL);
    if((int)lent !=1)
        return 0;//获取失败，返回 
    return get_next_m_ip(out);
}
//启动RING 0 RING 3 交互
int WINAPI init() {

    mydevice = CreateFile(DEVICE_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, NULL);
    if (mydevice == INVALID_HANDLE_VALUE)
    {
        return 0;
    }
    return 1;
}
//int WINAPI 

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

