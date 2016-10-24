import Consts
from scapy.layers.dns import dnstypes
from scapy.layers.dns import DNS

"""
    Check if counter of dns packet is valid
"""
def is_dns_counter_valid(counter):
    return counter >= 0 and counter <= 30

"""
    Check if all dns counters are vaild 
"""
def are_all_dns_counter_valid(pck):
    return is_dns_counter_valid(pck[DNS].ancount) and \
        is_dns_counter_valid(pck[DNS].nscount) and     \
        is_dns_counter_valid(pck[DNS].qdcount) and      \
        is_dns_counter_valid(pck[DNS].arcount)
        
"""
    Check if dns packet is malformed by check rcode and counters
"""
def is_dns_malformed_packet(pck):
    if pck.haslayer("DNS") and (pck[DNS].rcode != 0 or not are_all_dns_counter_valid(pck)):
        return True

"""
    Check if packet is DNS query
"""
def is_dns_query(pck):
    if pck.haslayer("DNS") and type(pck[DNS].qd) == str:
        import pdb
        pdb.set_trace()

    return (pck.haslayer("DNS") and
            dnstypes[pck[DNS].qd.qtype] == Consts.DNS_QUERY_TYPE and
            pck[DNS].qdcount == 1 and
            pck[DNS].ancount == 0 and
            Consts.NAT_IP == pck.getlayer("IP").src)

"""
    Check if packet is DNS response
"""
def is_dns_response(pck):
    return (pck.haslayer("DNS") and
            dnstypes[pck[DNS].qd.qtype] == Consts.DNS_QUERY_TYPE and
            pck[DNS].ancount != 0 and
            Consts.NAT_IP == pck["IP"].dst)

"""
    Get queried server name
""" 
def get_dns_query_name(pck):
    for dnsqr in pck[DNS].qd:
        if (dnstypes[dnsqr.qtype] == Consts.DNS_QUERY_TYPE):
            return dnsqr.qname

"""
    Get responses ip as list of DNS packet
"""
def get_dns_response_ip(pck):
    responses_ip = []
    for i in range(pck[DNS].ancount):
        if (dnstypes[pck[DNS].an[i].type] == Consts.DNS_QUERY_TYPE):
            responses_ip.append(pck[DNS].an[i].rdata)

    return responses_ip

"""
    Extract packets from pcap file
"""
def extract_packets(pcap_path):
    return rdpcap(pcap_path)    