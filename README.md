DISCONTINUATION OF PROJECT.

This project will no longer be maintained by Intel.

Intel has ceased development and contributions including, but not limited to, maintenance, bug fixes, new releases, or updates, to this project. 

Intel no longer accepts patches to this project.

If you have an ongoing need to use this project, are interested in independently developing it, or would like to maintain patches for the open source software community, please create your own fork of this project. 
========================================================================
README for Intel(R) rwpa_dp Package

February 2018
========================================================================


Contents
========

Contains C source-code and configuration files for the R-WPA dataplane application
which constitutes the Dataplane VNF part of the solution.

Overview
========

This application provide control and traffic forwarding, encryption\decryption,
encapsulation\decapsulation. Used TLS connection to VNF-C to get user authentication information
and receiving keys.

Configuration
=============

In the config directory contains configuration files for run this application
For example default.cfg
Section		Description
[EAL]		standart dpdk eal options.
[CRYPTO]	Crypto options, like are HW or SW crypto accelerator, crypto pairs etc.
[MEMPOOLX]	dpdk mempool. where X is mempool number
[LINKX]		mac address of PHY device. X - device number
[RXQX]		RX queues. configure binding the queue to mempool
[THREADX]	Describe uplink, downlink and statistic threads, used queues, cpus etc. X - thread number
[ADDRESSES]	Very important configuration section.
		You must configure next lines before run this application
		vnfd_ip_to_ap = ”VNFD IP address for connection to CMTS/CPE”
		vnfd_ip_to_wag = ”VNFD IP address for connection to WAG”
		wag_tun_ip = ”IP address of WAG”
		wag_tun_mac = ”MAC address of first hop on route to WAG”


How to build
============

For build your must define environment variable RTE_SDK - path to your DPDK
run make

How to run
==========

Firstly you need bind NIC interfaces with dpdk PMD driver.
(more information about dpdk pmd and how it work see on dpdk.org)

insmod x86_64-native-linuxapp-gcc/kmod/igb_uio.ko
./usertools/dpdk-devbind.py -b igb_uio 00:09.0 00:0a.0

in this example for bonding interfaces with driver was used dpdk script(dpdk-devbind.py).

See VNF documentation how to correct configure PCI interfaces.

./build/r-wpa2_dataplane -f ./config/default.cfg


Legal Disclaimer
================

THIS SOFTWARE IS PROVIDED BY INTEL"AS IS". NO LICENSE, EXPRESS OR
IMPLIED, BY ESTOPPEL OR OTHERWISE, TO ANY INTELLECTUAL PROPERTY RIGHTS
ARE GRANTED THROUGH USE. EXCEPT AS PROVIDED IN INTEL'S TERMS AND
CONDITIONS OF SALE, INTEL ASSUMES NO LIABILITY WHATSOEVER AND INTEL
DISCLAIMS ANY EXPRESS OR IMPLIED WARRANTY, RELATING TO SALE AND/OR
USE OF INTEL PRODUCTS INCLUDING LIABILITY OR WARRANTIES RELATING TO
FITNESS FOR A PARTICULAR PURPOSE, MERCHANTABILITY, OR INFRINGEMENT
OF ANY PATENT, COPYRIGHT OR OTHER INTELLECTUAL PROPERTY RIGHT.
