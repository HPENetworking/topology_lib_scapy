# -*- coding: utf-8 -*-
#
# Copyright (C) 2016 Hewlett Packard Enterprise Development LP
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

"""
topology_lib_scapy communication library implementation.
This library allows to send Scapy commands on host system that has Scapy
installed.
Packets can be defined using this library and then sent using Scapy.
Please refer to scapy documentation at
http://www.secdev.org/projects/scapy/doc/
to learn about Scapy

"""

from __future__ import unicode_literals, absolute_import
from __future__ import print_function, division
from .generator import createcdmline, protocol
import re
import threading


class ScapyThread(threading.Thread):
    def __init__(
            self, func, enode, topology,
            proto_str='', packet_list=[], filter_str='',
            count=0
               ):
        threading.Thread.__init__(self)
        self.func = func
        self.node = enode
        self.packet_list = packet_list
        self.proto_str = proto_str
        self.filter_str = filter_str
        self.args = (enode, proto_str, packet_list, topology, filter_str, count)

    def outresult(self):
        return self.res

    def run(self):
        self.res = self.func(*self.args)


def start_scapy(enode):
    """
    This method must be called before trying to send any scapy packets.

    Usage:

        ::

            <host node>.libs.scapy.start_scapy()

    """
    # Change bash prompt to scapy prompt
    host_type = str((type(enode)))
    host_type = host_type.replace("<class '", "")
    host_type = host_type[:-2]

    if host_type == "topology_docker.nodes.host.HostNode":
        enode._shells['bash']._prompt = '>>> '
        enode("/usr/local/bin/scapy", shell='bash')
    else:
        # enode._shells['bash']._backupprompt = enode._shells['bash']._prompt
        enode('apt-get install python-scapy', shell='bash')
        enode._shells['bash']._prompt = '>>> '
        enode("/usr/bin/scapy", shell='bash')


def exit_scapy(enode):
    """
    This method must be called after scapy commands are done. Not doing so
    may not allow for any bash commads to be sent for the host node.

    Usage:

        ::

            <host node>.libs.scapy.exit_scapy()

    """
    # Change scapy prompt to bash prompt
    host_type = str((type(enode)))
    host_type = host_type.replace("<class '", "")
    host_type = host_type[:-2]

    if host_type == "topology_docker.nodes.host.HostNode":
        enode._shells['bash']._prompt = '@~~==::BASH_PROMPT::==~~@'
    else:
        enode._shells['bash']._prompt = r'\r\n[^\r\n]+@.+[#$]'

    enode("exit()", shell='bash')


def ip(enode, key_val=None):
    """
    This method returns a dictionary for IP packet with keys. Initial
    values are set to none and can be changed.

    : param str key_val: fileds and values for IP packet.

    Usage:

        ::

            ip_packet = <host node>.libs.scapy.ip() or
            ip_packet = <host node>.libs.scapy.ip("dst='10.10.7.102',\
                                                    src='10.10.7.101'")

    """
    if enode._shells['bash']._prompt != '>>> ':
        start_scapy(enode)
        result = enode("IP().show()", shell='bash')
    else:
        result = enode("IP().show()", shell='bash')

    return protocol(result, key_val)


def ipv6(enode, key_val=None):
    """
    This method returns a dictionary for IPv6 packet with keys. Initial
    values are set to none and can be changed.

    : param str key_val: fileds and values for IPv6 packet.

    Usage:

        ::

            ipv6_packet = <host node>.libs.scapy.ipv6() or
            ipv6_packet = <host node>.libs.scapy.ipv6("dst=put ipv6 address,\
                                                    src=put ipv6 address")

    """
    if enode._shells['bash']._prompt != '>>> ':
        start_scapy(enode)
        result = enode("IPv6().show()", shell='bash')
    else:
        result = enode("IPv6().show()", shell='bash')

    return protocol(result, key_val)


def ether(enode, key_val=None):
    """
    This method returns a dictionary for Ether packet with keys. Initial
    values are set to none and can be changed.

    : param str key_val: fileds and values for packet.

    Usage:

        ::

            ether_packet = <host node>.libs.scapy.ether() or
            ether_packet = <host node>.libs.scapy.ether("type=0x9000")

    """
    if enode._shells['bash']._prompt != '>>> ':
        start_scapy(enode)
        result = enode("Ether().show()", shell='bash')
    else:
        result = enode("Ether().show()", shell='bash')

    return protocol(result, key_val)


def tcp(enode, key_val=None):
    """
    This method returns a dictionary for TCP packet with keys. Initial
    values are set to none and can be changed.

    : param str key_val: fileds and values for packet.

    Usage:

        ::

            tcp_packet = <host node>.libs.scapy.tcp() or
            tcp_packet = <host node>.libs.scapy.tcp("dport=179") or
            tcp_packet = <host node>.libs.scapy.tcp("dport=[179,100,(1,5)]")

    """
    if enode._shells['bash']._prompt != '>>> ':
        start_scapy(enode)
        result = enode("TCP().show()", shell='bash')
    else:
        result = enode("TCP().show()", shell='bash')

    return protocol(result, key_val)


def arp(enode, key_val=None):
    """
    This method returns a dictionary for ARP packet with keys. Initial
    values are set to none and can be changed.

    : param str key_val: fileds and values for packet.

    Usage:

        ::

            arp_packet = <host node>.libs.scapy.arp() or
            arp_packet = <host node>.libs.scapy.arp("<key>=<value>")

    """

    if enode._shells['bash']._prompt != '>>> ':
        start_scapy(enode)
        result = enode("ARP().show()", shell='bash')
    else:
        result = enode("ARP().show()", shell='bash')

    return protocol(result, key_val)


def icmp(enode, key_val=None):
    """
    This method returns a dictionary for ICMP packet with keys. Initial
    values are set to none and can be changed.

    : param str key_val: fileds and values for packet.

    Usage:

        ::

            icmp_packet = <host node>.libs.scapy.icmp() or
            icmp_packet = <host node>.libs.scapy.icmp("<key>=<value>")

    """
    if enode._shells['bash']._prompt != '>>> ':
        start_scapy(enode)
        result = enode("ICMP().show()", shell='bash')
    else:
        result = enode("ICMP().show()", shell='bash')

    return protocol(result, key_val)


def dot1q(enode, key_val=None):
    """
    This method returns a dictionary for Dot1Q packet with keys. Initial
    values are set to none and can be changed.

    : param str key_val: fileds and values for packet

    Usage:

        ::

            dot1q_packet = <host node>.libs.scapy.dot1q() or
            dot1q_packet = <host node>.libs.scapy.dot1q("<key>=<value>")

    """
    if enode._shells['bash']._prompt != '>>> ':
        start_scapy(enode)
        result = enode("Dot1Q().show()", shell='bash')
    else:
        result = enode("Dot1Q().show()", shell='bash')

    return protocol(result, key_val)


def udp(enode, key_val=None):
    """
    This method returns a dictionary for UDP packet with keys. Initial
    values are set to none and can be changed.

    : param str key_val: fileds and values for packet.

    Usage:

        ::

            udp_packet = <host node>.libs.scapy.udp() or
            udp_packet = <host node>.libs.scapy.udp("<key>=<value>")

    """
    if enode._shells['bash']._prompt != '>>> ':
        start_scapy(enode)
        result = enode("UDP().show()", shell='bash')
    else:
        result = enode("UDP().show()", shell='bash')

    return protocol(result, key_val)


# Send packets at layer 3
def send(enode, packet_struct, packet_list, options=None):
    """
    send: Send packets at layer 3

    : param type str
        packet_struct: Defines how packets are layered.eg: 'Eth/IP/TCP'
        options: optional parameters for the command, eg: "iface=1, count=1"
        param list: list of packets to be sent. eg: [ether, ip, tcp]

    Usage:

        ::

            result =\
            <node>.libs.scapy.send('Eth/IP/TCP', [ether, ip, tcp]) or
            <node>.libs.scapy.send('Eth/IP/TCP', [ether, ip, tcp], "iface=2")
    """

    packet = "send("
    scapycmd = createcdmline(packet, packet_struct, packet_list, options)
    return enode(scapycmd, shell='bash')


# Send packets at layer 2
def sendp(enode, packet_struct, packet_list, options=None):
    """
    Send packets at layer 2

    : param type str
        packet_struct: Defines how packets are layered.eg: 'Eth/IP/TCP'
        options: optional parameters for the command, eg: "iface=1, count=1"
        param list: list of packets to be sent. eg: [ether, ip, tcp]

    Usage:

        ::

            result =\
            <node>.libs.scapy.sendp('Eth/IP/TCP', [ether, ip, tcp]) or
            <node>.libs.scapy.sendp('Eth/IP/TCP', [ether, ip, tcp], "iface=2")
    """
    packet = "sendp("
    scapycmd = createcdmline(packet, packet_struct, packet_list, options)
    return enode(scapycmd, shell='bash')


# Send packets at layer 2 using tcpreplay for performance
def sendpfast(enode, packet_struct, packet_list, options=None):
    """
    Send packets at layer 2 fast

    : param type str
        packet_struct: Defines how packets are layered.eg: 'Eth/IP/TCP'
        options: optional parameters for the command, eg: "iface=1, count=1"
        param list: list of packets to be sent. eg: [ether, ip, tcp]

    Usage:

        ::

            result =\
                <node>.libs.scapy.sendpfast('Eth/IP/TCP', [ether, ip, tcp])

    """
    packet = "sendpfast("
    scapycmd = createcdmline(packet, packet_struct, packet_list, options)
    return enode(scapycmd, shell='bash')


# Sniff packets - timeout is 8 seconds by default.
def sniff(enode, options="timeout=5"):
    """
    Sniff command for host node. By default a timeout of 5 seconds
    has been set.
    Always include a timeout value < 9 seconds when specifying other options.

    : param type str
        options: optional parameters for the command, eg: "timeout=5"

    Usage:

        ::

            result =\
                <node>.libs.scapy.sniff("prn=None, lfilter=None, count=0,\
                 store=1, offline=None, L2socket=None,timeout=8")

            result = <node>.libs.scapy.sniff()
    """

    scapycmd = "sniff(" + options + ")"
    enode(scapycmd, shell='bash')
    return show(enode)


# Sniff packets - timeout is 8 seconds by default.
def sniff2(enode, options="timeout=5"):
    """
    Sniff command for host node. By default a timeout of 5 seconds
    has been set.
    Always include a timeout value < 9 seconds when specifying other options.

    : param type str
        options: optional parameters for the command, eg: "timeout=5"

    Usage:

        ::

            result =\
                <node>.libs.scapy.sniff("prn=None, lfilter=None, count=0,\
                 store=1, offline=None, L2socket=None,timeout=8")

            result = <node>.libs.scapy.sniff()
    """

    scapycmd = "sniff(" + options + ")"
    return enode(scapycmd, shell='bash')


# Generic Send and/or Receive Scapy Library Function
def srloop(enode, packet_struct, packet_list, options="timeout=5"):
    """
    Send and recieve multiple packets at layer 3
    Returns a string of received packets. Parser is yet to be implemented.
    By default, this returns a _.show() for the result.

    : param type str
        packet_struct: Defines how packets are layered.eg: 'Eth/IP/TCP'
        options: optional parameters for the command, eg: "iface=1, count=1"
        param list: list of packets to be sent. eg: [ether, ip, tcp]

    Usage:

        ::

            result =\
            <node>.libs.scapy.srloop('Eth/IP/TCP', [ether, ip, tcp]) or
            <node>.libs.scapy.srloop('Eth/IP/TCP', [ether, ip, tcp], "iface=2")
    """
    scapycmd = "srloop(" + options + ")"
    return enode(scapycmd, shell='bash')


# Send and receive packets at layer 3
def sr(enode, packet_struct, packet_list, options="timeout=5"):
    """
    Send and recieve packets at layer 3
    Returns a string of received packets. Parser is yet to be implemented.
    By default, this returns a _.show() for the result.

    : param type str
        packet_struct: Defines how packets are layered.eg: 'Eth/IP/TCP'
        options: optional parameters for the command, eg: "iface=1, count=1"
        param list: list of packets to be sent. eg: [ether, ip, tcp]

    Usage:

        ::

            result =\
            <node>.libs.scapy.sr('Eth/IP/TCP', [ether, ip, tcp]) or
            <node>.libs.scapy.sr('Eth/IP/TCP', [ether, ip, tcp], "iface=2")
    """
    packet = "sr("
    scapycmd = createcdmline(packet, packet_struct, packet_list, options)
    enode(scapycmd, shell='bash')
    return show(enode)


# Send packets at layer 3 and return only the first answer
def sr1(enode, packet_struct, packet_list, options="timeout=5"):
    """
    Send packets at layer 3 and return only the first answer
    Returns a string of received packet. Parser is yet to be implemented.
    By default, this returns a _.show() for the result.

    : param type str
        packet_struct: Defines how packets are layered.eg: 'Eth/IP/TCP'
        options: optional parameters for the command, eg: "iface=1, count=1"
        param list: list of packets to be sent. eg: [ether, ip, tcp]

    Usage:

        ::

            result =\
            <node>.libs.scapy.sr('Eth/IP/TCP', [ether, ip, tcp]) or
            <node>.libs.scapy.sr('Eth/IP/TCP', [ether, ip, tcp], "iface=2")
    """
    packet = "sr1("
    scapycmd = createcdmline(packet, packet_struct, packet_list, options)
    enode(scapycmd, shell='bash')
    # sleep(5)
    return show(enode)


# Send and receive packets at layer 2
def srp(enode, packet_struct, packet_list, options="timeout=5"):
    """
    Send and recieve packets at layer 2
    Returns a string of received packets. Parser is yet to be implemented.
    By default, this returns a _.show() for the result.

    : param type str
        packet_struct: Defines how packets are layered.eg: 'Eth/IP/TCP'
        options: optional parameters for the command, eg: "iface=1, count=1"
        param list: list of packets to be sent. eg: [ether, ip, tcp]

    Usage:

        ::

            result =\
            <node>.libs.scapy.srp('Eth/IP/TCP', [ether, ip, tcp]) or
            <node>.libs.scapy.srp('Eth/IP/TCP', [ether, ip, tcp], "iface=2")
    """
    packet = "srp("
    scapycmd = createcdmline(packet, packet_struct, packet_list, options)
    enode(scapycmd, shell='bash')
    return show(enode)


# Send and receive packets at layer 2 and return only the first answer
def srp1(enode, packet_struct, packet_list, options="timeout=5"):
    """
    Send packets at layer 2 and return only the first answer
    Returns a string of received packet. Parser is yet to be implemented.
    By default, this returns a _.show() for the result.

      : param type str
        packet_struct: Defines how packets are layered.eg: 'Eth/IP/TCP'
        options: optional parameters for the command, eg: "iface=1, count=1"
        param list: list of packets to be sent. eg: [ether, ip, tcp]

    Usage:

        ::

            result =\
            <node>.libs.scapy.srp1('Eth/IP/TCP', [ether, ip, tcp]) or
            <node>.libs.scapy.srp1('Eth/IP/TCP', [ether, ip, tcp], "iface=2")
    """
    packet = "srp1("
    scapycmd = createcdmline(packet, packet_struct, packet_list, options)
    enode(scapycmd, shell='bash')
    return show(enode)


def show(enode):
    """
    Return show() of the result as a string. This needs to be parsed.
    """
    result = enode("_.show()", shell='bash')
    return result


def summary(enode):
    """
    Return summary() of the result as a string. This needs to be parsed.
    """
    result = enode('_.summary()', shell='bash')
    return result


def get_prompt(enode):

    result = enode("echo '#!/bin/bash -i' >> myscript.sh", shell='bash')
    result = enode("echo 'echo \"$PS1\"' >> myscript.sh", shell='bash')
    result = enode("bash -i myscript.sh", shell='bash')
    prompt = "["
    prompttype1_re = r'(\[)(\\u)(@)(\\(h|H))\s+(\\W)(\])(\\\W)'
    prompttype2_re = r'(.*\})(\\u)(@)(\\(h|H):)(\\(w|W))(\\\$)'

    re_result = re.match(prompttype1_re, result)
    if re_result:
        prompt = prompt + enode("whoami", shell='bash') + "@"
        if re_result.group(5) == "h":
            prompt = prompt + enode("echo $(hostname)", shell='bash') + " "
        if re_result.group(5) == "H":
            prompt = prompt + enode("echo $(hostname)", shell='bash') + " "

        work_dir = enode("basename \"$PWD\"", shell='bash')
        if work_dir == "root":
            prompt = prompt + "~" + "]# "
        else:
            prompt = prompt + work_dir + "]$ "
        return prompt

    re_result = re.match(prompttype2_re, result)
    if re_result:
        prompt = enode("whoami", shell='bash') + "@"
        host_name = enode("cat /etc/hostname", shell='bash')
        if re_result.group(4) == "\h:":
            prompt = prompt + host_name + ":"
        if re_result.group(4) == "\H:":
            prompt = prompt + host_name + ":"

        work_dir = enode("basename \"$PWD\"", shell='bash')
        if work_dir == "root":
            prompt = prompt + "~" + "# "
        else:
            prompt = prompt + work_dir + "# "
        return prompt


__all__ = [
    'ScapyThread',
    'start_scapy',
    'exit_scapy',
    'send',
    'sendp',
    'sendpfast',
    'sr',
    'sr1',
    'srp',
    'srp1',
    'sniff',
    'sniff2',
    'ip',
    'ipv6',
    'tcp',
    'ether',
    'arp',
    'dot1q',
    'udp',
    'icmp',
    'show',
    'summary'
]
