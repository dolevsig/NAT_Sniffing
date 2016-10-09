class Stream:
    def __init__(self, pck):
        self._IPID = pck.getlayer("IP").id
        self._TTL = pck.getlayer("IP").ttl
        self._max_gap = 0
        self._qnames = set([pck.getlayer("DNS").qd.qname])
        self._pckts_traffic = []

    def update(self, pck):
        self._max_gap = max(self._max_gap, abs(self._IPID - pck.getlayer("IP").id))
        self._IPID = pck.getlayer("IP").id
        self._qnames.add(pck.getlayer("DNS").qd.qname)

    def is_contain_query_name(self, query_name):
        return (query_name in self._qnames)

    def insert_traffic(self, pck):
        self._pckts_traffic.append(pck)

    def get_ttl(self):
        return self._TTL

    def get_pckts_traffic(self):
        return self._pckts_traffic

    def get_IPID(self):
        return self._IPID