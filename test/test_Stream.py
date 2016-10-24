"""
    Class for DNS Stream
        _IPID - last IPID of the stream
        _TTL - time to live field in the packet
        _max_gap - maximum allowed gap between IPID
        _qnames - queried named in this stream
        _pckts_traffic - traffic packets that matched to this stream
"""
class Stream:
    def __init__(self, pck):
        self._IPID = pck.getlayer("IP").id
        self._TTL = pck.getlayer("IP").ttl
        self._max_gap = 0
        self._qnames = set([pck.getlayer("DNS").qd.qname])
        self._pckts_traffic = []

    """
        Update stream by new packet
    """
    def update(self, pck):
        self._max_gap = max(self._max_gap, abs(self._IPID - pck.getlayer("IP").id))
        self._IPID = pck.getlayer("IP").id
        self._qnames.add(pck.getlayer("DNS").qd.qname)
        
    """
        Check if query name queried in this stream
    """
    def is_contain_query_name(self, query_name):
        return (query_name in self._qnames)

    """
        Append traffic packet to the stream
    """        
    def insert_traffic(self, pck):
        self._pckts_traffic.append(pck)

    """
        Get ttl dictionary
    """
    def get_ttl(self):
        return self._TTL

    """
        Get all traffic packets of the stream
    """
    def get_pckts_traffic(self):
        return self._pckts_traffic

    """
        Get IPID attribute
    """
    def get_IPID(self):
        return self._IPID