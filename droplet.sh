#!/bin/sh
name=$1
region=$2
image=ubuntu-20-04-x64
size=s-2vcpu-4gb
sshkey=

[ -n "$name" ] || { echo NAME is required; exit 1; }

echo
echo SSH Keys:
doctl compute ssh-key ls --no-header
read -p "Choose an SSH Key: " _sshkey
[ -z "$_sshkey" ] || sshkey=$_sshkey

echo
echo Sizes:
cat <<EOF
s-1vcpu-1gb
s-3vcpu-1gb
s-2vcpu-4gb
s-4vcpu-8gb
s-8vcpu-16gb
EOF
read -p "Choose a Size ($size): " _size
[ -z "$_size" ] || size=$_size

if [ -z "$region" ]
then
    region=sfo2
    echo
    echo Regions:
    doctl compute region ls --no-header
    read -p "Choose a Region ($region): " _region
    [ -z "$_region" ] || region=$_region
fi

echo
doctl compute droplet create \
    --ssh-keys $sshkey \
    --region $region \
    --image $image \
    --size $size \
    --no-header \
    $name
