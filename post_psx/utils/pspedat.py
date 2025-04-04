import io
import struct

from post_psx.utils.base import BaseFile
from post_psx.utils.pgd import PGDFile


class PSPEdatFile(PGDFile, BaseFile):
    def __init__(self, fp, *_, **__):
        super().__init__(fp)
        self.fp.seek(0)
        self.decrypted_pgd = None
        magic = self.fp.read(0x8)
        if magic != b"\x00PSPEDAT":
            return
        self.fp.seek(0x0C)
        pgd_offset, = struct.unpack("<H", self.fp.read(2))
        self.fp.seek(pgd_offset)
        pgd_magic = self.fp.read(0x4)
        if pgd_magic != b"\x00PGD":
            return
        decrypted_pgd = self.decrypt_pgd(pgd_offset)
        self.size = self._size = len(decrypted_pgd)
        self.decrypted_pgd = io.BytesIO(decrypted_pgd)

    def read(self, size=-1):
        self.decrypted_pgd.seek(self._pos)
        data = self.decrypted_pgd.read(size)
        self._pos += len(data)
        return data
