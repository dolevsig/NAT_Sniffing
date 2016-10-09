from Stream import Stream
import Consts
import Utils
import logging
from Exceptions import NotFoundStream
from scapy.all import *

class Streams:
    def __init__(self):
        self._streams = []
        self._ip_to_stream_map = {}
        self._mismatch_pckts = []
        self._not_queried_pckt_counter = 0

    def _find_stream_index_by_query_name(self, query_name):
        for i, stream in enumerate(self._streams):
            if stream.is_contain_query_name(query_name):
                return i

        raise NotFoundStream(query_name)


    def _insert_ip_mapping(self, responses_ip, stream_index, query_name):
        for ip in responses_ip:
            self._ip_to_stream_map[ip] = stream_index

    def _update_with_response(self, pck):
        query_name = Utils.get_dns_query_name(pck)
        stream_index = self._find_stream_index_by_query_name(query_name)
        responses_ip = Utils.get_dns_response_ip(pck)
        self._insert_ip_mapping(responses_ip, stream_index, query_name)

    def _update_with_query(self, pck):
        for stream in self._streams:
            if (Consts.MAX_GAP_SIZE > abs(stream._IPID - pck[IP].id)):
                stream.update(pck)
                return

        self._streams.append(Stream(pck))

    def _update_with_traffic(self, pck):

        if (self._ip_to_stream_map.has_key(pck[IP].dst)):
            stream_index = self._ip_to_stream_map[pck[IP].dst]
        elif (self._ip_to_stream_map.has_key(pck[IP].src)):
            stream_index = self._ip_to_stream_map[pck[IP].src]
        else:
            self._mismatch_pckts.append(pck)
            return

        self._streams[stream_index].insert_traffic(pck)


    def update(self, pck):
        try:
            if (not pck.haslayer("IP")):
                return

            if (Utils.is_dns_query(pck)):
                self._update_with_query(pck)

            elif (Utils.is_dns_response(pck)):
                self._update_with_response(pck)

            elif (not self._is_src_or_dst_ip_was_queried(pck)):
                self._not_queried_pckt_counter +=1
            else:
                self._update_with_traffic(pck)

        except NotFoundStream as e:
            logging.warning("NotFoundStream exception was raise. response for query: %s", e._query_name)

    def _is_src_or_dst_ip_was_queried(self, pck):
        if (not pck.haslayer("IP")):
            return False

        return (self._ip_to_stream_map.has_key(pck[IP].dst) or
            self._ip_to_stream_map.has_key(pck[IP]))

    def get_ttl_count(self):
        ttl_count = {}
        for stream in self._streams:
            if (ttl_count.has_key(stream._TTL)):
                ttl_count[stream._TTL] +=1
            else:
                ttl_count[stream._TTL] = 1

        return ttl_count

    def get_mismatch_pckts(self):
        return self._mismatch_pckts

    def iter(self):
        for stream in self._streams:
            yield stream