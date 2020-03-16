from concurrent import futures
import ctypes
from ctypes import Structure, c_byte, c_uint
from dataclasses import dataclass
from enum import Enum
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


class TunnelFlag(Enum):
    FLAGS_IS_ACTIVE = 1 << 0


class TunnelEntry(Structure):
    _fields_ = [
        ("flags", c_uint),
        ("flow", TunnelFlow),
        ("ifindex", c_uint),
    ]


@dataclass
class DecapsProgramInfo:
    ifname: str
    prog: BPF # program attached to specified interface


@dataclass
class EncapsProgramInfo:
    ifname: str
    entry_index: int
    prog: BPF # program attached to specified interface


class EtherIPServicer(etherip_pb2_grpc.EtherIPServicer):
    def __init__(self):
        with open("datastore.c", "r") as f:
            text = f.read()
            self.datastore = BPF(text=text)

            self.entries = self.datastore.get_table("tunnel_entries")
            libbcc.lib.bpf_obj_pin(self.entries.map_fd, ctypes.c_char_p(b"/sys/fs/bpf/tunnel_entries"))

            self.lookup_table = self.datastore.get_table("tunnel_lookup_table")
            libbcc.lib.bpf_obj_pin(self.lookup_table.map_fd, ctypes.c_char_p(b"/sys/fs/bpf/tunnel_lookup_table"))

        self.ip = pyroute2.IPRoute()

        self.encaps_progs = {}
        self.decaps_progs = {}


    def ifname2ifindex(self, ifname):
        res = self.ip.link_lookup(ifname=ifname)

        if len(res) >= 1:
            return res[0]
        else:
            return None


    def create_new_etherip_tunnel_entry(self, flow):
        entry = TunnelEntry(c_uint(0), flow, c_uint(0))

        self.entries[c_uint(0)] = entry
        self.lookup_table[flow] = c_uint(0)

        return 0


    def CreateNewEtherIPTunnelEntry(self, req, ctx):
        remote_addr = IPv6Address(req.remote_addr)
        local_addr = IPv6Address(req.local_addr)

        flow = TunnelFlow(c_ipv6_addr(*remote_addr.packed), c_ipv6_addr(*local_addr.packed))
        entry_index = self.create_new_etherip_tunnel_entry(flow)

        if entry_index is None:
            pass

        return etherip_pb2.CreateNewEtherIPTunnelEntryResponse(entry_index=entry_index, request=req)


    def attach_encaps_program(self, ifname, entry_index):
        with open("encaps.c", "r") as f:
            text = f.read()
            prog = BPF(text=text, cflags=["-DENTRY_INDEX=%d" % entry_index])

        func = prog.load_func("entrypoint", BPF.XDP)
        prog.attach_xdp(ifname, func, 0)

        # update entry
        ifindex = self.ifname2ifindex(ifname)
        entry = self.entries[c_uint(entry_index)]
        entry.flags = c_uint(entry.flags | TunnelFlags.FLAGS_IS_ACTIVE.value)
        entry.ifindex = c_uint(ifindex)
        self.entries[c_uint(entry_index)] = entry

        self.encaps_progs[ifname] = EncapsProgramInfo(prog=prog, ifname=ifname, entry_index=entry_index)


    def detach_encaps_program(self, ifname):
        if not ifname in self.encaps_progs:
            pass

        info = self.encaps_progs[ifname]
        info.prog.remove_xdp(ifname, 0)

        entry_index = info.entry_index
        entry = self.entries[c_uint(entry_index)]
        entry.flags = c_uint(entry.flags & ~TunnelFlags.FLAGS_IS_ACTIVE.value)
        self.entries[c_uint(entry_index)] = entry

        del self.encaps_progs[ifname]


    def AttachEncapsProgram(self, req, ctx):
        ifname = req.ifname
        entry_index = int(req.entry_index)
        self.attach_encaps_program(ifname, entry_index)
        return etherip_pb2.AttachEncapsProgramResponse(request=req)


    def DetachEncapsProgram(self, req, ctx):
        ifname = req.ifname
        self.detach_encaps_program(ifname)
        return etherip_pb2.DetachEncapsProgramResponse(request=req)


    def attach_decaps_program(self, ifname):
        with open("decaps.c", "r") as f:
            text = f.read()
            prog = BPF(text=text)

        func = prog.load_func("entrypoint", BPF.XDP)
        prog.attach_xdp(ifname, func, 0)

        self.decaps_progs[ifname] = DecapsProgramInfo(prog=prog, ifname=ifname)


    def detach_decaps_program(self, ifname):
        if not ifname in self.decaps_progs:
            pass

        info = self.decaps_progs[ifname]
        info.prog.remove_xdp(ifname, 0)

        del self.decaps_progs[ifname]


    def AttachDecapsProgram(self, req, ctx):
        ifname = req.ifname
        self.attach_decaps_program(ifname)
        return etherip_pb2.AttachDecapsProgramResponse(request=req)


    def DetachDecapsProgram(self, req, ctx):
        ifname = req.ifname
        self.detach_decaps_program(ifname)
        return etherip_pb2.DetachDecapsProgramResponse(request=req)


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

