import re
import os
import sys
import json
import socket
import argparse
import subprocess


def get_default_gateway():
    p = subprocess.Popen(["ip", "route"], stdout=subprocess.PIPE)
    out, _ = p.communicate()
    if p.returncode != 0:
        raise Exception("Listing routes failed.")
    lines = out.decode("utf-8").strip().split(os.linesep)
    if len(lines) == 0:
        raise Exception("No routes found.")
    table = {}
    for line in lines:
        parts = line.strip().split(" ")
        network = parts[0]
        if network not in table:
            table[network] = []
        table[network].append(
            {parts[i + 1]: parts[i + 2] for i in range(0, len(parts) - 2, 2)}
        )
    return next(
        iter(sorted(table["default"], key=lambda item: int(item.get("metric", 10000))))
    )


def parse_address(address):
    address, bits = address.split("/", 1)
    bits = int(bits)
    shift = 32 - bits
    # address
    addrbytes = socket.inet_aton(address)
    addrint = int.from_bytes(addrbytes, "big")
    # network
    netint = (addrint >> shift) << shift
    netbytes = netint.to_bytes(4, "big")
    network = socket.inet_ntoa(netbytes)
    # gateway
    gwbytes = (netint + 1).to_bytes(4, "big")
    gateway = socket.inet_ntoa(gwbytes)
    # netmask
    maskint = ((1 << bits) - 1) << shift
    netmask = socket.inet_ntoa(maskint.to_bytes(4, "big"))
    return {
        "network": network,
        "address": address,
        "gateway": gateway,
        "netmask": netmask,
        "bits": bits,
    }


def parse_peerstxt(filename):
    peers = []
    with open(filename) as f:
        contents = f.read().strip()
    for line in contents.strip().split(os.linesep):
        name, endpoint, listenport, address, publickey = re.split(
            "\s+", line.strip(), 4
        )
        peers.append(
            {
                "name": name,
                "endpoint": endpoint,
                "listenport": listenport,
                "address": address,
                "publickey": publickey,
            }
        )
    return peers


def get_current_member(members, privatekey_file):
    with open(privatekey_file) as f:
        privatekey = f.read().strip()
    p = subprocess.Popen(
        ["wg", "pubkey"], stdin=subprocess.PIPE, stdout=subprocess.PIPE
    )
    stdout, _ = p.communicate(privatekey.encode("utf-8"))
    publickey = stdout.decode("utf-8").strip()
    for member in members:
        if member["publickey"] == publickey:
            return member
    raise Exception(f"Member not found for public key: {publickey}")


def get_member_by_name(members, name):
    for member in members:
        if member["name"] == name:
            return member
    raise Exception(f"Unable to find member with name: {name}")


class Script(object):
    def __init__(
        self, members, wgiface, route_via, privatekey_file, default_gateway, name
    ):
        self.wgiface = wgiface
        self.route_via = route_via
        self.gateway_address = default_gateway["via"]
        self.gateway_iface = default_gateway["dev"]
        self.privatekey_file = privatekey_file
        self.members = members
        if name is None:
            self.current = get_current_member(members, privatekey_file)
        else:
            self.current = get_member_by_name(members, name)
        self.name = self.current["name"]
        self.listenport = self.current["listenport"]
        net = parse_address( self.current["address"])
        self.wgnetwork = net["network"] + "/" + str(net["bits"])
        self.wgaddress = net["address"]
        self.wgnetmask = net["netmask"]

    def up(self, config):
        self.add_link(config)
        self.wg_set(config)
        self.enable_link(config)
        self.add_address(config)

    def down(self, config):
        self.del_address(config)
        self.disable_link(config)
        self.del_link(config)

    def enable_route_via(self, config):
        target = get_member_by_name(self.members, self.route_via)
        if target["endpoint"] == "-":
            raise Exception(f"Unable to route via {self.name}. Endpoint is required.")
        config.append(f"ip route add 0.0.0.0/1 dev {self.wgiface}")
        config.append(f"ip route add 128.0.0.0/1 dev {self.wgiface}")
        config.append(
            f"ip route add {target['endpoint']}/32 via {self.gateway_address} "
            f"dev {self.gateway_iface}"
        )

    def disable_route_via(self, config):
        target = get_member_by_name(self.members, self.route_via)
        if target["endpoint"] == "-":
            raise Exception(f"Unable to route via {self.name}. Endpoint is required.")
        config.append(f"ip route del 128.0.0.0/1 dev {self.wgiface}")
        config.append(f"ip route del 0.0.0.0/1 dev {self.wgiface}")
        config.append(
            f"ip route del {target['endpoint']}/32 via {self.gateway_address} "
            f"dev {self.gateway_iface}"
        )

    def enable_router(self, config):
        config.append(
            "iptables -t nat -S POSTROUTING | grep -q MASQUERADE || iptables "
            f"-t nat -A POSTROUTING -o {self.gateway_iface} -j MASQUERADE"
        )
        config.append(
            "sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g' /etc/sysctl.conf"
        )
        config.append("sysctl -w net.ipv4.ip_forward=1")
        config.append("sysctl -p")

    def add_link(self, config):
        config.append(f"ip link add {self.wgiface} type wireguard")

    def del_link(self, config):
        config.append(f"ip link del {self.wgiface}")

    def enable_link(self, config):
        config.append(f"ip link set {self.wgiface} up")

    def disable_link(self, config):
        config.append(f"ip link set {self.wgiface} down")

    def add_address(self, config):
        config.append(f"ip addr add {self.current['address']} dev {self.wgiface}")

    def del_address(self, config):
        config.append(
            f"ip addr del {self.current['address']} dev {self.wgiface} || /bin/true"
        )

    def wg_set(self, config):
        config.append(f"wg set {self.wgiface} listen-port {self.listenport}")
        config.append(f"wg set {self.wgiface} private-key {self.privatekey_file}")

        for peer in self.members:
            if peer["name"] == self.current["name"]:
                continue
            peerkey = peer["publickey"]
            if peer["name"] == self.route_via:
                config.append(
                    f"wg set {self.wgiface} peer {peerkey} allowed-ips 0.0.0.0/0"
                )
            else:
                peeraddr = peer["address"].split("/", 1)[0]
                config.append(
                    f"wg set {self.wgiface} peer {peerkey} allowed-ips {peeraddr}/32"
                )
            if peer["endpoint"] != "-":
                peeraddr = peer["endpoint"]
                peerport = peer["listenport"]
                config.append(
                    f"wg set {self.wgiface} peer {peerkey} endpoint {peeraddr}:{peerport}"
                )


def _action_up(args):
    members = parse_peerstxt(args.filename)
    default_gateway = get_default_gateway()
    config = []
    script = Script(
        members,
        args.wgiface,
        args.route_via,
        args.privatekey_file,
        default_gateway,
        args.name,
    )
    script.up(config)
    if args.enable_router:
        script.enable_router(config)
    elif args.route_via:
        script.enable_route_via(config)
    _run_commands(args, config)


def _action_down(args):
    members = parse_peerstxt(args.filename)
    default_gateway = get_default_gateway()
    config = []
    script = Script(
        members,
        args.wgiface,
        args.route_via,
        args.privatekey_file,
        default_gateway,
        args.name,
    )
    if args.route_via:
        script.disable_route_via(config)
    script.down(config)
    _run_commands(args, config)


def _action_interfaces(args):
    members = parse_peerstxt(args.filename)
    default_gateway = get_default_gateway()
    config = []
    script = Script(
        members,
        args.wgiface,
        args.route_via,
        args.privatekey_file,
        default_gateway,
        args.name,
    )
    config = []
    config.append(f"auto lo")
    config.append(f"iface lo inet loopback")
    config.append("")
    config.append(f"auto {script.gateway_iface}")
    config.append(f"iface {script.gateway_iface} inet dhcp")
    config.append("")
    config.append(f"auto {script.wgiface}")
    config.append(f"iface {script.wgiface} inet static")
    config.append(f"    address {script.wgaddress}")
    config.append(f"    network {script.wgnetwork}")
    config.append(f"    netmask {script.wgnetmask}")
    pre_up = []
    script.add_link(pre_up)
    script.wg_set(pre_up)
    script.enable_link(pre_up)
    for cmd in pre_up:
        config.append(f"    pre-up {cmd}")
    post_down = []
    if script.route_via:
        script.disable_route_via(post_down)
    script.disable_link(post_down)
    script.del_link(post_down)
    for cmd in post_down:
        config.append(f"    post-down {cmd}")
    print(os.linesep.join(config))


def _run_commands(args, commands):
    for line in commands:
        if args.apply:
            print(">>", line)
            p = subprocess.Popen(line, shell=True)
            p.wait()
            print("<< code", p.returncode)
            if p.returncode != 0:
                raise Exception("Command failed: " + line)
        else:
            print(line)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-f", dest="filename", type=os.path.abspath, default="peers.txt"
    )
    parser.add_argument(
        "-k", dest="privatekey_file", type=os.path.abspath, default="privatekey"
    )
    parser.add_argument("-i", "--wgiface", default="wg0")
    parser.add_argument(
        "-a", "--action", choices=["down", "up", "interfaces"], required=True
    )
    parser.add_argument("-n", "--name", default=None)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--route-via", default=None)
    group.add_argument("--enable-router", action="store_true")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()

    if args.action == "up":
        _action_up(args)
    elif args.action == "down":
        _action_down(args)
    elif args.action == "interfaces":
        _action_interfaces(args)


if __name__ == "__main__":
    main()
