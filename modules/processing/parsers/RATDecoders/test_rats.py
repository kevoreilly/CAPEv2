from malwareconfig.common import Decoder

# https://youtu.be/C_ijc7A5oAc?list=OLAK5uy_kGTSX7lmPmKwIVzgFLqd0x3dSF6HQhE-I

class TEST_RATS(Decoder):
    decoder_name = "TestRats"
    decoder__version = 1
    decoder_author = "doomedraven"
    decoder_description = "Test module to ensure that framework loads properly."

    def __init__(self):
        pass
