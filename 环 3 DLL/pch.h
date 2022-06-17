// pch.h: 这是预编译标头文件。
// 下方列出的文件仅编译一次，提高了将来生成的生成性能。
// 这还将影响 IntelliSense 性能，包括代码完成和许多代码浏览功能。
// 但是，如果此处列出的文件中的任何一个在生成之间有更新，它们全部都将被重新编译。
// 请勿在此处添加要频繁更新的文件，这将使得性能优势无效。

#ifndef PCH_H
#define PCH_H
// 添加要在此处预编译的标头
#include "framework.h"
#pragma once

extern "C" __declspec(dllexport) int WINAPI ipv4_new_rule(int flag, int ip[], int _port, int S_Or_R, int S_Or_D);
extern "C" __declspec(dllexport) int WINAPI ipv6_new_rule(int flag, int ip[], int _port, int S_Or_R, int S_Or_D);
extern "C" __declspec(dllexport) int WINAPI start();
extern "C" __declspec(dllexport) int WINAPI stop();
extern "C" __declspec(dllexport) int WINAPI init();
extern "C" __declspec(dllexport) int WINAPI dele(int flag);
extern "C" __declspec(dllexport) int WINAPI process_new_rule(int flag,int PID, int S_Or_R);
extern "C" __declspec(dllexport) int WINAPI dele_all();
extern "C" __declspec(dllexport) int WINAPI get_m_ip_num();
extern "C" __declspec(dllexport) int WINAPI get_first_m_ip(OUT int *out);
extern "C" __declspec(dllexport) int WINAPI get_next_m_ip(OUT int *out);
#endif //PCH_H
