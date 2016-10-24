from Initializer import initializer

class Summary:
    @initializer
    def __init__(self, filename, is_correct_coloring, error_info, mismatch_pckts, ttl_count):
        pass

"""
    Check if the coloring is correct using TTL
"""
def is_correct_coloring(streams):

    is_correct = True
    wrong_pckts = []
    for stream in streams.iter():
        ttl = stream.get_ttl()
        for pck in stream.get_pckts_traffic():
            if (ttl != pck["IP"].ttl):
                is_correct = False
                wrong_pckts.append([stream.get_IPID(), pck])

    return is_correct, wrong_pckts

"""
    create Stream summary instance
"""    
def create_summary(streams, filename):

    is_correct, wrong_pckts_info = is_correct_coloring(streams)
    return Summary(filename, is_correct, wrong_pckts_info, streams.get_mismatch_pckts(), streams.get_ttl_count())