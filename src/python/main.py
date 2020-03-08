from concurrent import futures
import grpc 

import etherip_pb2
import etherip_pb2_grpc


class EtherIPServicer(etherip_pb2_grpc.EtherIPServicer):
    def __init__(self):
        pass

    def CreateNewEtherIPTunnelEntry(self, req, ctx):
        pass

    def AttachEncapsProgram(self, req, ctx):
        pass

    def AttachDecapsProgram(self, req, ctx):
        pass


def main():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=64))

    servicer = EtherIPServicer()
    etherip_pb2_grpc.add_EtherIPServicer_to_server(servicer, server)

    server.add_insecure_port("0.0.0.0:31337")
    server.start()
    server.wait_for_termination()


if __name__ == "__main__":
    main()
