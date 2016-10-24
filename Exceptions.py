from Initializer import initializer
"""
    Exception for not found traffic destination packtet in the response ips
"""
class NotFoundStream(Exception):
    @initializer
    def __init__(self, query_name):
        pass
    