#!/usr/sbin/nft -f


# Limpa todas as regras existentes
flush ruleset


# Cria uma tabela para IPv6
table ip6 filter {
    # Define um conjunto dinâmico para a blacklist de endereços IPv6
    set blacklist {
        type ipv6_addr
        flags dynamic, timeout # Permite adicionar/remover dinamicamente e definir timeout
        # auto-merge # Opcional: para otimizar a inserção de elementos
    }


    # Cadeia para tráfego destinado ao próprio gateway (input)
    chain input {
        type filter hook input priority 0; policy drop;


        # 1. Permite tráfego na interface de loopback
        iif "lo" accept


        # 2. Permite tráfego de conexões estabelecidas e relacionadas
        ct state established,related accept


        # 3. Descarta pacotes inválidos (sem estado ou com estado desconhecido)
        ct state invalid drop


        # 4. Permite ICMPv6 essencial para o funcionamento do IPv6
        ip6 nexthdr icmpv6 icmpv6 type { 
            destination-unreachable, 
            packet-too-big, 
            time-exceeded, 
            parameter-problem 
        } accept


        # 5. Permite tráfego NDP (Neighbor Discovery Protocol) apenas link-local
        ip6 saddr fe80::/10 ip6 nexthdr icmpv6 icmpv6 type { 
            nd-router-solicit, 
            nd-router-advert, 
            nd-neighbor-solicit, 
            nd-neighbor-advert 
        } accept


        # 6. Limita requisições de echo (ping) para evitar ataques de inundação
        ip6 nexthdr icmpv6 icmpv6 type echo-request limit rate 10/second burst 30 packets accept
        ip6 nexthdr icmpv6 icmpv6 type echo-reply accept


        # 7. Bloqueia todo o restante do ICMPv6 não explicitamente permitido
        ip6 nexthdr icmpv6 drop


        # 8. Bloqueia tráfego originado de IPs na blacklist
        ip6 saddr @blacklist drop


        # 9. Permite SSH apenas da rede interna (exemplo: interface LAN eth0)
        # iif "eth0" tcp dport 22 accept


        # 10. Permite acesso a serviços web no gateway (se houver)
        # tcp dport { 80, 443 } accept


        # 11. Loga e descarta o restante do tráfego não permitido
        limit rate 5/minute log prefix "nftables-input-drop: " level info drop
    }


    # Cadeia para tráfego roteado através do gateway (forward)
    chain forward {
        type filter hook forward priority 0; policy drop;


        # 1. Permite tráfego de conexões estabelecidas e relacionadas
        ct state established,related accept


        # 2. Permite ICMPv6 essencial (packet-too-big para PMTUD)
        ip6 nexthdr icmpv6 icmpv6 type packet-too-big accept


        # 3. Bloqueia tráfego originado ou destinado a IPs na blacklist
        ip6 saddr @blacklist drop
        ip6 daddr @blacklist drop


        # 4. Permite tráfego da LAN (eth0) para a WAN (eth1)
        iif "eth0" oif "eth1" accept


        # 5. Permite tráfego da WAN (eth1) para a LAN (eth0) apenas para respostas estabelecidas
        # (já coberto por ct state established,related accept)


        # 6. Loga e descarta o restante do tráfego não permitido
        limit rate 5/minute log prefix "nftables-forward-drop: " level info drop
    }


    # Cadeia para tráfego originado pelo próprio gateway (output)
    chain output {
        type filter hook output priority 0; policy accept;


        # Opcional: Anti-spoofing para garantir que o tráfego de saída use o prefixo correto
        # ip6 saddr != 2001:db8:corp::/48 drop # Habilitar se necessário, ajustando o prefixo
    }
}
