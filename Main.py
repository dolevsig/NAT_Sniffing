from Streams import Streams
import Consts
import os
import Summary

def filter_only_win_10(pckts):
    return pckts.filter(lambda pck: pck.haslayer("IP") and (pck[IP].ttl == 144 or pck[IP].ttl == 139))

"""
    Create DNS Streams and match traffic packets to matched stream
"""    
def create_streams(pckts):
    streams = Streams()
    for i, pck in enumerate(pckts):
            streams.update(pck)

    return streams

def main(pcap_folder):
    summaries = []
    fls = os.listdir(pcap_folder)
    for filename in fls:
    #filename = r"D:\temp\win_2.cap"
    pckts = Utiils.extract_packets(os.path.join(pcap_folder, filename))
    #pckts = filter_only_win_10(pckts)
    streams_by_IPID = create_streams(pckts)
    summary = Summary.create_summary(streams_by_IPID, filename)
    summaries.append(summary)

    import pdb
    pdb.set_trace()

if __name__ == "__main__":
    main(Consts.PCAP_FOLDER)