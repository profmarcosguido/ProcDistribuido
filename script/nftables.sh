table ip6 filter {
# Define um conjunto dinâmico para a blacklist
# 'flags dynamic' permite adicionar/remover elementos em tempo de execução
# 'timeout' pode ser usado para expirar entradas automaticamente (opcional)
set blacklist {
type ipv6_addr
flags dynamic
}

# Cadeia para tráfego destinado ao próprio gateway
chain input {
    type filter hook input priority 0; policy drop;

    # Permite tráfego na interface de loopback
    iif "lo" accept

    # Permite tráfego de conexões estabelecidas e relacionadas
    ct state established,related accept

    # Descarta pacotes inválidos
    ct state invalid drop

    # Permite ICMPv6 essencial (NDP, Ping, etc.)
    ip6 nexthdr icmpv6 accept

    # Bloqueia tráfego originado de IPs na blacklist
    ip6 saddr @blacklist drop

    # Permite SSH apenas da rede interna (exemplo)
    # iif "eth0" tcp dport 22 accept
}

# Cadeia para tráfego roteado através do gateway (LAN <-> WAN)
chain forward {
    type filter hook forward priority 0; policy drop;

    # Permite tráfego de conexões estabelecidas e relacionadas
    ct state established,related accept

    # Bloqueia tráfego originado ou destinado a IPs na blacklist
    ip6 saddr @blacklist drop
    ip6 daddr @blacklist drop

    # Permite tráfego da LAN para a WAN
    iif "eth0" oif "eth1" accept
}

# Cadeia para tráfego originado pelo próprio gateway
chain output {
    type filter hook output priority 0; policy accept;
}

}