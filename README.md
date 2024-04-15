# My Firewall Module

## Table of Contents
- [Introduction](#introduction)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [File Descriptions](#file-descriptions)

## Introduction
My Firewall Module is a Linux kernel module that provides a simple packet filtering and rate-limiting firewall functionality. It allows users to configure rules to either accept or drop incoming network packets based on the protocol (TCP/UDP) and optionally apply rate-limiting to prevent abuse.

This repository contains both the kernel module (my_firewall.c) and a userspace application (user_app_firewall.c) that communicates with the kernel module using custom IOCTL commands.

## Features
- Packet filtering: The firewall can selectively accept or drop incoming TCP and UDP packets based on configurable rules.
- Rate-limiting: Users can enable rate-limiting to control the number of packets allowed from the same source IP within a specified time interval.
- Dynamic connection tracking: The kernel module automatically tracks active connections and removes expired connections to ensure efficient use of resources.

## Prerequisites
- Linux Kernel Headers: Make sure you have the appropriate Linux kernel headers installed for your kernel version.
- GCC Compiler: The kernel module requires a C compiler to be installed on your system.

## Installation
1. Clone this repository to your local machine.
2. Navigate to the repository directory containing the kernel module source code.

## Usage
### Building and Installing the Kernel Module
1. Open a terminal in the repository directory.
2. Run the following commands to build and install the kernel module:
```
   make
   sudo insmod my_firewall.ko
```
File Descriptions
- my_firewall.c: The main source code of the Linux kernel module implementing the firewall functionality.
- user_app_firewall.c: Source code for the userspace application that communicates with the kernel module using IOCTL commands.
- Device File Permissions
  The device file /dev/my_firewall_device is created with the following permissions:
- Read and Write: Owner
- Read: Group and Others


