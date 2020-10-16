#!/bin/bash
action=$1
subaction=$2
user=root
files="peers.txt wgconfig.py"
set -e
if [ "$action" = provision ]
then
    echo -n > peers.txt
    while read name endpoint listenport address
    do
        echo --- Provisioning $name $endpoint --- >&2
        if [ "$endpoint" != "-" ]
        then
            echo -n > $name.log
            cat <<EOF | ssh $user@$endpoint >>$name.log 2>&1
set -ex
apt update
apt install wireguard wireguard-tools
mkdir -p /etc/wireguard
cd /etc/wireguard
[ -f privatekey ] || { umask 077 ; wg genkey > privatekey ; }
EOF
            publickey=$(ssh -n $user@$endpoint 'wg pubkey < /etc/wireguard/privatekey' < /dev/null)
        else
            publickey=$(wg pubkey < privatekey)
        fi
        echo "$name\t$endpoint\t$listenport\t$address\t$publickey" >> peers.txt
    done < seed.txt
elif [ "$action" = start ]
then
    while read name endpoint listenport address publickey
    do
        echo --- Starting $name $endpoint ---
        if [ "$endpoint" != "-" ]
        then
            tar -Ocv $files | ssh $user@$endpoint " \
                tar -C /etc/wireguard -xvf - ; \
                cd /etc/wireguard ; \
                python3 wgconfig.py -a '$subaction' --enable-router --apply" >>$name.log 2>&1
        else
            sudo python3 wgconfig.py -a "$subaction" --apply >>$name.log 2>&1
        fi
    done < peers.txt
else
    echo "./$(basename $0) (provision|start) (up|down)"
    exit 1
fi
