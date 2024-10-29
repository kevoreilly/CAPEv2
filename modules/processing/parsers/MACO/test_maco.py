from maco.extractor import Extractor


class Test(Extractor):
    author = "test"
    family = "test"
    last_modified = "2024-10-20"

    def run(self, stream, matches):
        pass
