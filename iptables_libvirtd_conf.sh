iptables -A INPUT -i virbr0 -j ACCEPT && iptables -A OUTPUT -o virbr0 -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED -j ACCEPT
iptables -A INPUT -j DROP
iptables -A OUTPUT -j DROP

