#!/usr/sbin/nft -f

flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;

        # Accept traffic from the loopback interface
        iifname "lo" accept

        # Accept incoming SSH, HTTP, and HTTPS connections on enp9s0
        tcp dport { 22, 80, 443 } ct state { new, established } iifname "enp9s0" accept
        
        # Accept established and related connections
        ct state { related, established } accept
        
        # Allow ICMP types 0 (Echo Reply) and 8 (Echo Request)
        icmp type { echo-request, echo-reply } accept

        # Allow DNS responses (UDP and TCP) from port 53
        udp sport 53 ct state { related, established } accept
        tcp sport 53 ct state { related, established } accept

        # Log and drop remaining packets (rate-limited to 2/minute)
        limit rate 2/minute log prefix "NFT Packet Dropped: " level debug
        drop
    }

    chain forward {
        type filter hook forward priority 0; policy drop;
    }

    chain output {
        type filter hook output priority 0; policy drop;

        # Accept outgoing traffic from loopback interface
        oifname "lo" accept

        # Accept established outgoing SSH, HTTP, and HTTPS connections
        tcp sport { 22, 80, 443 } ct state established oifname "enp9s0" accept
        tcp dport { 22, 80, 443 } ct state { new, established } oifname "enp9s0" accept

        # Accept DNS requests (UDP and TCP) to port 53
        udp dport 53 ct state { new, related, established } oifname "enp9s0" accept
        tcp dport 53 ct state { new, related, established } oifname "enp9s0" accept

        # Accept established connections
        ct state established accept

        # Allow ICMP types 0 (Echo Reply) and 8 (Echo Request)
        icmp type { echo-request, echo-reply } accept
    }
}