#pragma once

#define WIN32_LEAN_AND_MEAN             // 从 Windows 头文件中排除极少使用的内容
// Windows 头文件
//#include <windows.h>
#include<Windows.h>
//#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#include<malloc.h>
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
    //UCHAR flag[20];//对应使用的过滤函数：1使用，0不使用，预留20个过滤条件函数的位置
    long long B;//占位用的，无实际意义
    long long A;//占位用的，无实际意义

}Filter_Condition, * PFilter_Condition;
typedef struct record {
    UCHAR v4_or_v6;
    union
    {
        UCHAR ipv4[4];
        UCHAR ipv6[16];
    }IP;
    long long s;//占位用的，无实际意义
}Record, * PRecord;
