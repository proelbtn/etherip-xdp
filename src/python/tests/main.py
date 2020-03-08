import grpc

import etherip_pb2
import etherip_pb2_grpc


def main():
    with grpc.insecure_channel("localhost:31337") as chan:
        stub = etherip_pb2_grpc.EtherIPStub(chan)

        res = stub.CreateNewEtherIPTunnelEntry(etherip_pb2.CreateNewEtherIPTunnelEntryRequest(
                src_addr="2409:252:a00:f200::1111",
                dst_addr="2409:252:a00:f200::2222"))
        print(res)

        res = stub.AttachDecapsProgram(etherip_pb2.AttachDecapsProgramRequest(
                ifname="ens18"))
        print(res)

        res = stub.AttachEncapsProgram(etherip_pb2.AttachEncapsProgramRequest(
                ifname="ens19",
                entry_index=0))
        print(res)


if __name__ == "__main__":
    main()
