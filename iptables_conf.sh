function set_network_rules(){
  local net_dev="$1"

  iptables -F
  iptables -P INPUT DROP
  iptables -P FORWARD DROP
  iptables -P OUTPUT DROP

  #Allow ALL Incoming SSH
  iptables -A INPUT -i "${net_dev}" -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
  iptables -A OUTPUT -o "${net_dev}" -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT

  #Allow Incoming SSH only from a Specific Network
  #iptables -A INPUT -i eth0 -p tcp -s 192.168.100.0/24 --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
  #iptables -A OUTPUT -o eth0 -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT

  #Allow Incoming HTTP and HTTPS
  iptables -A INPUT -i "${net_dev}" -p tcp --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
  iptables -A OUTPUT -o "${net_dev}" -p tcp --sport 80 -m state --state ESTABLISHED -j ACCEPT

  iptables -A INPUT -i "${net_dev}" -p tcp --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT
  iptables -A OUTPUT -o "${net_dev}" -p tcp --sport 443 -m state --state ESTABLISHED -j ACCEPT

  #Combine Multiple Rules Together using MultiPorts
  iptables -A INPUT -i "${net_dev}" -p tcp -m multiport --dports 22,80,443 -m state --state NEW,ESTABLISHED -j ACCEPT
  iptables -A OUTPUT -o "${net_dev}" -p tcp -m multiport --sports 22,80,443 -m state --state ESTABLISHED -j ACCEPT

  #Allow Outgoing SSH
  iptables -A OUTPUT -o "${net_dev}" -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
  iptables -A INPUT -i "${net_dev}" -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT

  #Allow Outgoing SSH only to a Specific Network
  #iptables -A OUTPUT -o eth0 -p tcp -d 192.168.100.0/24 --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
  #iptables -A INPUT -i eth0 -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT

  #Allow Outgoing HTTPS
  iptables -A OUTPUT -o "${net_dev}" -p tcp --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT
  iptables -A INPUT -i "${net_dev}" -p tcp --sport 443 -m state --state ESTABLISHED -j ACCEPT

  #DNS
#  iptables -A OUTPUT -p udp -o "${net_dev}" --dport 53 -j ACCEPT
#  iptables -A INPUT -p udp -i "${net_dev}" --sport 53 -j ACCEPT
#  iptables -A OUTPUT -p tcp -o "${net_dev}" --dport 53 -j ACCEPT
#  iptables -A INPUT -p tcp -i "${net_dev}" --sport 53 -j ACCEPT
# 4below ???
  iptables -A OUTPUT -p udp -o "${net_dev}" --dport 53 -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT
  iptables -A INPUT -p udp -i "${net_dev}" --sport 53 -m state --state RELATED,ESTABLISHED -j ACCEPT
  iptables -A OUTPUT -p tcp -o "${net_dev}" --dport 53 -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT
  iptables -A INPUT -p tcp -i "${net_dev}" --sport 53 -m state --state RELATED,ESTABLISHED -j ACCEPT

  ##Load Balances - uses the iptables nth extension
  #iptables -A PREROUTING -i eth0 -p tcp --dport 443 -m state --state NEW -m nth --counter 0 --every 3 --packet 0 -j DNAT --to-destination 192.168.1.101:443
  #iptables -A PREROUTING -i eth0 -p tcp --dport 443 -m state --state NEW -m nth --counter 0 --every 3 --packet 1 -j DNAT --to-destination 192.168.1.102:443
  #iptables -A PREROUTING -i eth0 -p tcp --dport 443 -m state --state NEW -m nth --counter 0 --every 3 --packet 2 -j DNAT --to-destination 192.168.1.103:443

  #transmission
  iptables -A INPUT -p tcp -i "${net_dev}" --sport 49152 -j ACCEPT
  iptables -A INPUT -p tcp -i "${net_dev}" --sport 65535 -j ACCEPT
  iptables -A INPUT -p udp -i "${net_dev}" --sport 51413 -j ACCEPT
  iptables -A INPUT -p tcp -i "${net_dev}" --sport 60812 -j ACCEPT
  iptables -A INPUT -p udp -i "${net_dev}" --dport 51413 -j ACCEPT
  iptables -A INPUT -p udp -i "${net_dev}" --dport 60812 -j ACCEPT

  iptables -A OUTPUT -p udp -o "${net_dev}" --sport 51413 -j DROP
  iptables -A OUTPUT -p tcp -o "${net_dev}" --sport 60812 -j DROP
  iptables -A OUTPUT -p tcp -o "${net_dev}" --dport 51413 -j DROP
  iptables -A OUTPUT -p tcp -o "${net_dev}" --dport 60812 -j DROP

  #allow loopback communication
  iptables -A INPUT -i lo -j ACCEPT
  iptables -A OUTPUT -o lo -j ACCEPT

  #Allow Ping from Outside to Inside
  iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
  iptables -A OUTPUT -p icmp --icmp-type echo-reply -j ACCEPT

  #Allow Ping from Inside to Outside
  iptables -A OUTPUT -p icmp --icmp-type echo-request -j ACCEPT
  iptables -A INPUT -p icmp --icmp-type echo-reply -j ACCEPT

  iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED -j ACCEPT

  #allow ntp, sntp
  iptables -A INPUT -p udp --dport 123 -j ACCEPT
  iptables -A OUTPUT -p udp --dport 123 -j ACCEPT


  iptables -A INPUT -s 192.168.124.1 -j ACCEPT
  iptables -A OUTPUT -d 192.168.124.1 -j ACCEPT
  iptables -A INPUT -s 192.168.124.150 -j ACCEPT
  iptables -A OUTPUT -d 192.168.124.150 -j ACCEPT

  #Allow Internal Network to External network (if 2 devices exists)
  #iptables -A FORWARD -i eth1 -o eth0 -j ACCEPT

  #logging
  iptables -X LOGGING
  iptables -N LOGGING
  iptables -A INPUT -j LOGGING
  iptables -A LOGGING -m limit --limit 2/min -j LOG --log-prefix "IPTABLES Packet Dropped: " --log-level 7
  iptables -A LOGGING -j DROP
}

set_network_rules $1
