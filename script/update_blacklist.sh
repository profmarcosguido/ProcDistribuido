#!/bin/bash
 
BLACKLIST_URL="https://your_wazuh_server/ipv6_blacklist.txt"
LOCAL_BLACKLIST="/tmp/ipv6_blacklist.txt"
NFT_TABLE="ip6 filter"
NFT_SET="blacklist"
 
# Baixa a blacklist mais recente
wget -q -O "$LOCAL_BLACKLIST" "$BLACKLIST_URL"
 
if [ $? -ne 0 ]; then
    echo "Erro ao baixar a blacklist do $BLACKLIST_URL" >> /var/log/blacklist_update.log
    exit 1
fi
 
# Obtém a lista atual de IPs no conjunto nftables
CURRENT_IPS=$(nft list set $NFT_TABLE $NFT_SET | grep -Eo '([0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}' || true)
CURRENT_IPS_ARRAY=($CURRENT_IPS)
 
# Lê a nova blacklist
NEW_IPS=$(cat "$LOCAL_BLACKLIST" || true)
NEW_IPS_ARRAY=($NEW_IPS)
 
# Adiciona novos IPs ao conjunto nftables
for new_ip in "${NEW_IPS_ARRAY[@]}"; do
    if ! printf '%s\n' "${CURRENT_IPS_ARRAY[@]}" | grep -q -w "$new_ip"; then
        nft add element $NFT_TABLE $NFT_SET { $new_ip }
        echo "$(date): Adicionado $new_ip à blacklist." >> /var/log/blacklist_update.log
    fi
done
 
# Remove IPs que não estão mais na blacklist (opcional, se houver timeout no set)
# for current_ip in "${CURRENT_IPS_ARRAY[@]}"; do
#     if ! printf '%s\n' "${NEW_IPS_ARRAY[@]}" | grep -q -w "$current_ip"; then
#         nft delete element $NFT_TABLE $NFT_SET { $current_ip }
#         echo "$(date): Removido $current_ip da blacklist." >> /var/log/blacklist_update.log
#     fi
# done
 
rm "$LOCAL_BLACKLIST"
