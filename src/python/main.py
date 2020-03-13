from concurrent import futures
import ctypes
from ctypes import Structure, c_byte, c_uint
from ipaddress import IPv6Address, AddressValueError

from bcc import BPF, libbcc
import grpc 
import pyroute2

import etherip_pb2
import etherip_pb2_grpc


c_ipv6_addr = c_byte * 16

class TunnelFlow(Structure):
    _fields_ = [
        ("remote_addr", c_ipv6_addr),
        ("local_addr", c_ipv6_addr),
    ]


class TunnelEntry(Structure):
    _fields_ = [
        ("flow", TunnelFlow),
        ("ifindex", c_uint),
    ]


class EtherIPServicer(etherip_pb2_grpc.EtherIPServicer):
    def __init__(self):
        with open("datastore.c", "r") as f:
            text = f.read()
            self.datastore = BPF(text=text)

            self.entries = self.datastore.get_table("tunnel_entries")
            libbcc.lib.bpf_obj_pin(self.entries.map_fd, ctypes.c_char_p(b"/sys/fs/bpf/tunnel_entries"))

            self.lookup_table = self.datastore.get_table("tunnel_lookup_table")
            libbcc.lib.bpf_obj_pin(self.entries.map_fd, ctypes.c_char_p(b"/sys/fs/bpf/tunnel_lookup_table"))

        self.ip = pyroute2.IPRoute()

        self.encaps_progs = []
        self.decaps_progs = []


    def ifname2ifindex(self, ifname):
        res = self.ip.link_lookup(ifname=ifname)

        if len(res) >= 1:
            return res[0]
        else:
            return None


    def create_new_etherip_tunnel_entry(self, flow):
        entry = TunnelEntry(flow, c_uint(0xffffffff))

        self.entries[c_uint(0)] = entry
        self.lookup_table[flow] = c_uint(0)

        return 0


    def CreateNewEtherIPTunnelEntry(self, req, ctx):
        try:
            remote_addr = IPv6Address(req.remote_addr)
        except AddressValueError:
            return etherip_pb2.CreateNewEtherIPTunnelEntryResponse(
                    result=-1, entry_index=-1, request=req)

        try:
            local_addr = IPv6Address(req.local_addr)
        except AddressValueError:
            return etherip_pb2.CreateNewEtherIPTunnelEntryResponse(
                    result=-1, entry_index=-1, request=req)


        flow = TunnelFlow(c_ipv6_addr(*remote_addr.packed), c_ipv6_addr(*local_addr.packed))
        entry_index = self.create_new_etherip_tunnel_entry(flow)

        if entry_index is None:
            return etherip_pb2.CreateNewEtherIPTunnelEntryResponse(
                    result=-1, entry_index=entry_index, request=req)

        return etherip_pb2.CreateNewEtherIPTunnelEntryResponse(
                result=0, entry_index=entry_index, request=req)


    def attach_encaps_program(self, ifname, entry_index):
        with open("encaps.c", "r") as f:
            text = f.read()
            prog = BPF(text=text, cflags=["-DENTRY_INDEX=%d" % entry_index])

        func = prog.load_func("entrypoint", BPF.XDP)
        prog.attach_xdp(ifname, func, 0)

        self.encaps_progs.append(prog)

        # update entry
        ifindex = self.ifname2ifindex(ifname)
        entry = self.entries[c_uint(entry_index)]

        entry.ifindex = c_uint(ifindex)

        self.entries[c_uint(entry_index)] = entry

        return 0


    def AttachEncapsProgram(self, req, ctx):
        ifname = req.ifname

        try:
            entry_index = int(req.entry_index)
        except ValueError:
            return etherip_pb2.AttachEncapsProgramResponse(
                    result=-1, request=req)

        res = self.attach_encaps_program(ifname, entry_index)

        return etherip_pb2.AttachEncapsProgramResponse(
                result=res, request=req)


    def attach_decaps_program(self, ifname):
        with open("decaps.c", "r") as f:
            text = f.read()
            prog = BPF(text=text)

        func = prog.load_func("entrypoint", BPF.XDP)
        prog.attach_xdp(ifname, func, 0)

        self.decaps_progs.append(prog)

        return 0


    def AttachDecapsProgram(self, req, ctx):
        ifname = req.ifname

        res = self.attach_decaps_program(ifname)

        return etherip_pb2.AttachDecapsProgramResponse(
                result=res, request=req)


def main():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=64))

    servicer = EtherIPServicer()
    etherip_pb2_grpc.add_EtherIPServicer_to_server(servicer, server)

    print("starting...")
    server.add_insecure_port("0.0.0.0:31337")
    server.start()
    server.wait_for_termination()


if __name__ == "__main__":
    main()

