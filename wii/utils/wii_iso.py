import logging
from io import BytesIO
from pathlib import Path

from dolreader.dol import DolFile
from pyisotools.apploader import Apploader
from pyisotools.bi2 import BI2
from pyisotools.boot import Boot
from pyisotools.fst import FSTNode
from pyisotools.iso import GamecubeISO

from wii.utils.disc import Disc
from wii.utils.partition import Partition

LOGGER = logging.getLogger(__name__)


class WiiISO(GamecubeISO):
    def __init__(self):
        super().__init__()
        self.partition = None

    @classmethod
    def from_disc(cls, iso: Path, disc: Disc):
        for partition_info in disc.partitions:
            if partition_info.type == 0:
                LOGGER.info("Found data partition index %d", partition_info.index)
                return cls.from_partition(iso, Partition(disc, partition_info))

    @classmethod
    def from_partition(cls, iso: Path, part: Partition):
        virtualISO = cls()
        virtualISO.init_from_partition(iso, part)
        return virtualISO

    def init_from_partition(self, iso: Path, part: Partition):
        self.isoPath = iso
        self.partition = part

        part.seek(0)
        self.bootheader = Boot(part)
        self.bootheader.fstSize <<= 2
        self.bootheader.fstOffset <<= 2
        self.bootheader.dolOffset <<= 2
        self.bootinfo = BI2(part)
        self.apploader = Apploader(part)
        self.dol = DolFile(part, startpos=self.bootheader.dolOffset)
        part.seek(self.bootheader.fstOffset)
        self._rawFST = BytesIO(part.read(self.bootheader.fstSize))

        self.load_file_systemv(self._rawFST)

        prev = FSTNode.file("", None, self.bootheader.fstSize, self.bootheader.fstOffset)
        for node in self.nodes_by_offset():
            alignment = self._detect_alignment(node, prev)
            if alignment != 4:
                self._alignmentTable[node.path] = alignment
            prev = node

    def _read_nodes(self, fst, node: FSTNode, strTabOfs: int) -> FSTNode:
        node = super()._read_nodes(fst, node, strTabOfs)
        if node._fileoffset:
            node._fileoffset <<= 2
        return node
