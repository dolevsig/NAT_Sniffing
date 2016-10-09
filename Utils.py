import Consts
from scapy.layers.dns import dnstypes
from scapy.layers.dns import DNS

def is_dns_query(pck):
    return (pck.haslayer("DNS") and
            dnstypes[pck[DNS].qd.qtype] == Consts.DNS_QUERY_TYPE and
            pck[DNS].qdcount == 1 and
            pck[DNS].ancount == 0 and
            Consts.NAT_IP == pck.getlayer("IP").src)

def is_dns_response(pck):
    return (pck.haslayer("DNS") and
            dnstypes[pck[DNS].qd.qtype] == Consts.DNS_QUERY_TYPE and
            pck[DNS].ancount != 0 and
            Consts.NAT_IP == pck["IP"].dst)

def get_dns_query_name(pck):
    for dnsqr in pck[DNS].qd:
        if (dnstypes[dnsqr.qtype] == Consts.DNS_QUERY_TYPE):
            return dnsqr.qname

def get_dns_response_ip(pck):
    responses_ip = []
    for i in range(pck[DNS].ancount):
        if (dnstypes[pck[DNS].an[i].type] == Consts.DNS_QUERY_TYPE):
            responses_ip.append(pck[DNS].an[i].rdata)

    return responses_ip