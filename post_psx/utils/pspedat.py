import io
import logging
import struct

from post_psx.utils.base import BaseFile
from post_psx.utils.pgd import PGDFile

LOGGER = logging.getLogger(__name__)


class PSPEdatFile(PGDFile, BaseFile):
    def __init__(self, fp, file_name=None, *_, **__):
        super().__init__(fp)
        self.file_name = file_name
        self.fp.seek(0)
        self.decrypted_pgd = None
        # decrypt_pgd returns False on a bad DNAS flag or a failed MAC check, and the
        # magic checks can bail out before we get that far, so start out undecrypted
        self.decrypted = False
        self.size = self._size = 0
        magic = self.fp.read(0x8)
        if magic != b"\x00PSPEDAT":
            LOGGER.warning("Not a PSP EDAT (magic %s) in %s", magic, self.fp_name)
            return
        self.fp.seek(0x0C)
        pgd_offset, = struct.unpack("<H", self.fp.read(2))
        self.fp.seek(pgd_offset)
        pgd_magic = self.fp.read(0x4)
        if pgd_magic != b"\x00PGD":
            LOGGER.warning("Unsupported PSP EDAT payload (magic %s at 0x%x) in %s",
                           pgd_magic, pgd_offset, self.fp_name)
            return
        decrypted_pgd = self.decrypt_pgd(pgd_offset)
        if not decrypted_pgd:
            return
        self.decrypted = True
        self.size = self._size = len(decrypted_pgd)
        self.decrypted_pgd = io.BytesIO(decrypted_pgd)

    def read(self, size=-1):
        self.decrypted_pgd.seek(self._pos)
        data = self.decrypted_pgd.read(size)
        self._pos += len(data)
        return data
