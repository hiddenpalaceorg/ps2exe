from xbox.xdvdfs.directory import Directory
from xbox.xdvdfs.volume import Volume


class XDvdFs:
    def __init__(self, fp, offset):
        self.fp = fp
        self.volume = Volume(fp, offset)
        self.root = Directory(fp, self.volume, self.volume.root_directory_sector, None)