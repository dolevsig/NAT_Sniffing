from Initializer import initializer

class Summary:
    @initializer
    def __init__(self, is_correct_coloring, error_info, mismatch_pckts, ttl_count):
        pass

def is_correct_coloring(streams):

    for stream in streams.iter():
        ttl = stream.get_ttl()
        for pck in stream.get_pckts_traffic():
            if (ttl != pck["IP"].ttl):
                return False, [stream.get_IPID(), pck]

    return True, []

def create_summary(streams, filename):

    is_correct, wrong_pckts_info = is_correct_coloring(streams)
    return Summary(is_correct, wrong_pckts_info, streams.get_mismatch_pckts(), streams.get_ttl_count())