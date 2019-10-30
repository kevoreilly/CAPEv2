#!/bin/sh
sudo ovs-vsctl add-br lan0
for tap in `seq 0 4`; do
        sudo ip tuntap add mode tap lan0p$tap
done;
sudo ip tuntap list
for tap in `seq 0 4`; do
        sudo ip link set lan0p$tap up
done;
sudo ip link
for tap in `seq 0 4`; do
       sudo ovs-vsctl add-port lan0 lan0p$tap
done;
sudo ovs-vsctl list-ports lan0
#sudo ovs-vsctl -- --id=@m create mirror name=mirror3 select_all=1 -- add bridge lan0 mirrors @m

#mirror port
sudo modprobe dummy
sudo ip link set up dummy0
sudo ifconfig dummy0 promisc -arp
sudo ovs-vsctl -- --may-exist add-port lan0 dummy0
sudo ovs-vsctl -- --id=@p get port dummy0 -- --id=@m create mirror name=mirror0 select_all=1 -- add bridge lan0 mirrors @m -- set mirror mirror0 output_port=@p
#mgmt
sudo ovs-vsctl add-port lan0 lan0hp0 -- set interface lan0hp0 type=internal
sudo ip addr add 192.168.1.1 dev lan0hp0
sudo ip link set lan0hp0 up
sudo ip route add 192.168.1.0/24 dev lan0hp0
