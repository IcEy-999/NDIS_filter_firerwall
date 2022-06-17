# NDIS Filter firewall

本项目包含四个部分：

驱动部分：NDIS_Driver

RING 3 DLL：RING 3 DLL

GUI：GUI

成品部分；



##### 项目说明

驱动部分详细说明查看 NDIS_Driver文件夹内的 “NDIS Driver Readme.pdf”

DLL部分详细说明查看 Ring 3 DLL 文件夹内的 “Ring 3 DLL Readme.pdf”

GUI部分详细说明查看 GUI文件夹内的 “GUI E Readme.pdf”

成品部分：驱动未签名，需要签名或禁止签名强制性启动后才可以正常安装。易语言编译的GUI许多杀毒软件会误报，无视即可。





驱动部分是利用微软开源的NDIS filter 框架进行二次开发。



前端GUI是利用易语言编写，主要和RING0通信的函数都在 RING 3 DLL中实现。

前端和功能分离，方便利用不同的语言进行前端绘制。



不建议安装在物理机，这只是玩具！