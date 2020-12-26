import struct

from p3do.operafs.root import Root
from p3do.operafs.volume import Volume


class SuperBlock:
    SIZE = 132
    FMT = f'>b{Volume.SIZE}s{Root.SIZE}s'

    def __init__(self, fp):
        self.fp = fp
        self.version, volume, root  = struct.unpack(self.FMT, self.fp.read(self.SIZE))
        self.volume = Volume(volume)
        self.root = Root(fp, root)

