from .superblock import SuperBlock

class OperaFs:
    superblock = None
    def __init__(self, fp):
        self.fp = fp

    def initialize(self):
        self.fp.seek(0)
        self.superblock = SuperBlock(self.fp)
        return self.superblock