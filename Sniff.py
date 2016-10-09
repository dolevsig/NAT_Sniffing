from scapy.all import *

from Streams import Streams
import Consts
import os
import Summary

def extract_packets(pcap_path):
    return rdpcap(pcap_path)

def create_streams(pckts):
    streams = Streams()
    for i, pck in enumerate(pckts):
            streams.update(pck)

    return streams

def main(pcap_folder):
    summaries = []
    for filename in os.listdir(pcap_folder):
        pckts = extract_packets(os.path.join(pcap_folder, filename))
        streams_by_IPID = create_streams(pckts)
        summary = Summary.create_summary(streams_by_IPID, filename)
        summaries.append(summary)

    import pdb
    pdb.set_trace()

if __name__ == "__main__":
    main(Consts.PCAP_FOLDER)