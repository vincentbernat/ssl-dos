#!/bin/sh

# Copyright (c) 2011 Vincent Bernat <bernat@luffy.cx>
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

IPTABLES=/sbin/iptables

# 1. Limit number of connection
#####################################
$IPTABLES -F LIMIT_SSL 2> /dev/null
$IPTABLES -X LIMIT_SSL 2> /dev/null
$IPTABLES -N LIMIT_SSL
$IPTABLES -A LIMIT_SSL \
    -p tcp \
    --syn -m state --state NEW \
    -m hashlimit \
    --hashlimit-above 120/minute --hashlimit-burst 20 \
    --hashlimit-mode srcip --hashlimit-name ssl-conn \
    -j DROP

# 2. Limit number of renegociation
#####################################
$IPTABLES -F LIMIT_RENEGOCIATION 2> /dev/null
$IPTABLES -X LIMIT_RENEGOCIATION 2> /dev/null
$IPTABLES -N LIMIT_RENEGOCIATION
payload="0 >> 22 & 0x3C @ 12 >> 26 & 0x3C @" # Access to TCP payload (if not fragmented)
$IPTABLES -A LIMIT_RENEGOCIATION \
    -p tcp \
    --tcp-flags SYN,FIN,RST,PSH PSH \
    -m u32 \
    --u32 "$payload 0 >> 8 = 0x160300:0x160303 && $payload 2 & 0xFF = 3:10,17:19,21:255" \
    -m hashlimit \
    --hashlimit-above 5/minute --hashlimit-burst 3 \
    --hashlimit-mode srcip --hashlimit-name ssl-reneg \
    -j DROP

# Example of use:
# $IPTABLES -A FORWARD -d 192.0.2.15 -p tcp --dport 443 -j LIMIT_SSL
# $IPTABLES -A FORWARD -d 192.0.2.15 -p tcp --dport 443 -j LIMIT_RENEGOCIATION
# $IPTABLES -A FORWARD -d 192.0.2.15 -p tcp --dport 443 -j ACCEPT
