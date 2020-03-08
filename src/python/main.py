from bcc import BPF, libbcc
from concurrent import futures
import ctypes
import grpc 
from ipaddress import IPv6Address, AddressValueError

import etherip_pb2
import etherip_pb2_grpc


class EtherIPServicer(etherip_pb2_grpc.EtherIPServicer):
    def __init__(self):
        with open("datastore.c", "r") as f:
            text = f.read()
            self.datastore = BPF(text=text)

            self.entries = self.datastore.get_table("tunnel_entries")
            libbcc.lib.bpf_obj_pin(self.entries.map_fd, ctypes.c_char_p(b"/sys/fs/bpf/tunnel_entries"))

            self.lookup_table = self.datastore.get_table("tunnel_lookup_table")
            libbcc.lib.bpf_obj_pin(self.entries.map_fd, ctypes.c_char_p(b"/sys/fs/bpf/tunnel_lookup_table"))

        self.encaps_progs = []
        self.decaps_progs = []


    def create_new_etherip_tunnel_entry(self, src, dst):
        pass


    def CreateNewEtherIPTunnelEntry(self, req, ctx):
        try:
            src_addr = IPv6Address(req.src_addr)
        except AddressValueError:
            return etherip_pb2.CreateNewEtherIPTunnelEntryResponse(
                    result=-1, entry_index=-1, request=req)

        try:
            dst_addr = IPv6Address(req.dst_addr)
        except AddressValueError:
            return etherip_pb2.CreateNewEtherIPTunnelEntryResponse(
                    result=-1, entry_index=-1, request=req)

        return etherip_pb2.CreateNewEtherIPTunnelEntryResponse(
                result=0, entry_index=0, request=req)


    def attach_encaps_program(self, ifname, entry_ifindex):
        with open("encaps.c", "r") as f:
            text = f.read()
            prog = BPF(text=text)

        func = prog.load_func("entrypoint")
        prog.attach_xdp(ifname, func, 0)

        self.encaps_progs.append(prog)

        return 0


    def AttachEncapsProgram(self, req, ctx):
        ifname = req.ifname

        try:
            entry_ifindex = int(req.entry_index)
        except ValueError:
            return etherip_pb2.AttachEncapsProgramResponse(
                    result=-1, request=req)

        res = self.attach_encaps_program(self, ifname, entry_ifindex)

        return etherip_pb2.AttachEncapsProgramResponse(
                result=res, request=req)


    def attach_decaps_program(self, ifname):
        with open("decaps.c", "r") as f:
            text = f.read()
            prog = BPF(text=text)

        func = prog.load_func("entrypoint")
        prog.attach_xdp(ifname, func, 0)

        self.decaps_progs.append(prog)

        return 0


    def AttachDecapsProgram(self, req, ctx):
        ifname = req.ifname

        res = self.attach_encaps_program(self, ifname)

        return etherip_pb2.AttachEncapsProgramResponse(
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

