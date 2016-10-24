from Initializer import initializer

class Test_Class:
    @initializer
    def __init__(self, a, b, c):
        pass

def test_initializer():
    cl = Test_Class(1,2,3)
    assert hasattr(a, cl) and hasattr(b, cl) and hasattr(c, cl)