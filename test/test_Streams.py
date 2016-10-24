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

    """
        Get the index of stream that contain query_name
    """
    def _find_stream_index_by_query_name(self, query_name):
        for i, stream in enumerate(self._streams):
            if stream.is_contain_query_name(query_name):
                return i

        raise NotFoundStream(query_name)

    """
        Insert to mapping new record
    """
    def _insert_ip_mapping(self, responses_ip, stream_index, query_name):
        for ip in responses_ip:
            self._ip_to_stream_map[ip] = stream_index

    """
        Update streams with dns response.
        First find the matched stream and then insert mapping to the query response
    """
    def _update_with_response(self, pck):
        query_name = Utils.get_dns_query_name(pck)
        stream_index = self._find_stream_index_by_query_name(query_name)
        responses_ip = Utils.get_dns_response_ip(pck)
        self._insert_ip_mapping(responses_ip, stream_index, query_name)

    """
        Update streams with dns query.
        In case query is match for existing stream, update the stream. Otherwise create new stream.
    """
    def _update_with_query(self, pck):
        for stream in self._streams:
            if (Consts.MAX_GAP_SIZE > abs(stream._IPID - pck[IP].id)):
                stream.update(pck)
                return

        self._streams.append(Stream(pck))

    """
        Update streams with traffic packet.
        First find matched existing streams and then append the packet.
    """
    def _update_with_traffic(self, pck):

        if (self._ip_to_stream_map.has_key(pck[IP].dst)):
            stream_index = self._ip_to_stream_map[pck[IP].dst]
        elif (self._ip_to_stream_map.has_key(pck[IP].src)):
            stream_index = self._ip_to_stream_map[pck[IP].src]
        else:
            self._mismatch_pckts.append(pck)
            return

        self._streams[stream_index].insert_traffic(pck)

    """
        Update streams with packet.
        The update is dependent on the type of the packet.
    """
    def update(self, pck):
        try:
            if (not pck.haslayer("IP") or Utils.is_dns_malformed_packet(pck)):
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
    """
        Check if the source or the destination of the packer was queried
    """
    def _is_src_or_dst_ip_was_queried(self, pck):
        if (not pck.haslayer("IP")):
            return False

        return (self._ip_to_stream_map.has_key(pck[IP].dst) or
            self._ip_to_stream_map.has_key(pck[IP]))

    """
        Get ttl count dictionary. The key is the TTL and value is number of the streams
    """
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