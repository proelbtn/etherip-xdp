from concurrent import futures
import grpc 
from ipaddress import IPv6Address, AddressValueError

import etherip_pb2
import etherip_pb2_grpc


class EtherIPServicer(etherip_pb2_grpc.EtherIPServicer):
    def __init__(self):
        pass

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

    def attach_encaps_program(self, ifindex, entry_ifindex):
        pass

    def AttachEncapsProgram(self, req, ctx):
        try:
            ifindex = int(req.ifindex)
        except ValueError:
            return etherip_pb2.AttachEncapsProgramResponse(
                    result=-1, request=req)

        try:
            entry_ifindex = int(req.entry_index)
        except ValueError:
            return etherip_pb2.AttachEncapsProgramResponse(
                    result=-1, request=req)

        return etherip_pb2.AttachEncapsProgramResponse(
                result=0, request=req)

    def attach_decaps_program(self, ifindex):
        pass

    def AttachDecapsProgram(self, req, ctx):
        try:
            ifindex = int(req.ifindex)
        except ValueError:
            return etherip_pb2.AttachEncapsProgramResponse(
                    result=-1, request=req)

        return etherip_pb2.AttachEncapsProgramResponse(
                result=0, request=req)


def main():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=64))

    servicer = EtherIPServicer()
    etherip_pb2_grpc.add_EtherIPServicer_to_server(servicer, server)

    server.add_insecure_port("0.0.0.0:31337")
    server.start()
    server.wait_for_termination()


if __name__ == "__main__":
    main()
