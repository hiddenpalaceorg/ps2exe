import collections
import functools
import io
import logging
import math
import os
import pathlib
import sqlite3
import struct

from Crypto.Cipher import AES
from pycdlib.pycdlibio import PyCdlibIO

from common.iso_path_reader.methods.pycdlib import PyCdLibPathReader

LOGGER = logging.getLogger(__name__)


class DecryptedFileReader(PyCdlibIO):
    def __init__(self, ino, logical_block_size, disc_key):
        super().__init__(ino, logical_block_size)
        self.disc_key = disc_key

    def read(self, size=None):
        if self._offset >= self._length:
            return super().read(size)

        read_size = min(size or (self._length - self._offset), self._length - self._offset)
        orig_pos = self._fp.tell()
        orig_offset = self._offset
        read_offset = self._fp.tell() % 2048
        if read_offset != 0:
            self._offset -= read_offset
            self._fp.seek(-read_offset, os.SEEK_CUR)
        num_chunks = math.ceil((read_size + read_offset) / 2048)
        if read_offset + read_size > 2048 * num_chunks:
            num_chunks += 1
        decrypted = io.BytesIO()
        bytes_read = 0
        for chunk in range(num_chunks):
            block = super().read(min(size, 2048))
            if not block:
                break
            bytes_read += len(block)
            # Read the remainder of the sector
            if len(block) != 2048:
                block += self._fp.read(2048 - len(block))
            decrypted.write(self.decrypt_block(block, self.disc_key))

        self._offset = orig_offset + read_size
        self._fp.seek(orig_pos + read_size)
        decrypted.seek(read_offset)
        return decrypted.read(read_size)

    def decrypt_block(self, block, disc_key):
        if not disc_key:
            return block

        pos = (self._fp.tell() // 2048) - 1
        iv = bytearray(b'\x00' * 16)

        for j in range(16):
            iv[16 - j - 1] = (pos & 0xFF)
            pos >>= 8

        cipher = AES.new(disc_key, AES.MODE_CBC, bytes(iv))
        return cipher.decrypt(block)

class Ps3PathReader(PyCdLibPathReader):
    def __init__(self, iso, fp, *args, **kwargs):
        super().__init__(iso, fp, *args, **kwargs)
        self.fp.seek(0)
        self.number_of_unencrypted_regions = struct.unpack('>i4x', self.fp.read(8))
        self.regions = self.get_regions()
        self.disc_key = None
        self.disc_key = self.get_disc_key()

    def get_regions(self):
        Region = collections.namedtuple("Region", "start end encrypted")

        # The first region is always unencrypted
        encrypted = False
        start, end = struct.unpack(">ll", self.fp.read(8))
        regions = [
            Region(
                start=start * self.iso.logical_block_size,
                end=end * self.iso.logical_block_size + self.iso.logical_block_size,
                encrypted=encrypted
            )
        ]

        while True:
            encrypted = not encrypted
            end, = struct.unpack('>l', self.fp.read(4))
            if not end:
                break

            start = regions[-1].end
            regions.append(Region(
                start=start,
                end=end * self.iso.logical_block_size - (self.iso.logical_block_size if encrypted else 0),
                encrypted=encrypted
            ))

        return regions

    def get_disc_key(self):
        first_encrypted_region = next((region for region in self.regions if region.encrypted), None)
        if not first_encrypted_region:
            LOGGER.info("Found unencrypted disc, no key required")
            return

        try:
            with DecryptedFileReader(self.get_file("/PS3_GAME/USRDIR/EBOOT.BIN").inode, self.iso.logical_block_size, None) as f:
                block = f.read(2048)
                expected_magic = b'SCE\x00\x00\x00\x00'
        except FileNotFoundError:
            with DecryptedFileReader(self.get_file("/PS3_GAME/LICDIR/LIC.DAT").inode, self.iso.logical_block_size, None) as f:
                block = f.read(2048)
                expected_magic = b'PS3LICD'

        if block[:7] in expected_magic:
            LOGGER.info("Found decrypted disc, no key required")
            return

        # Check if there exists a 32 byte hexadecimal or 16 byte file in the same dir. That may be the key
        file_dir = self.parent_container.get_file(str(pathlib.Path(self.fp.name).parent))
        for i in self.parent_container.iso_iterator(file_dir):
            if self.parent_container.get_file_size(i) == 32:
                try:
                    key = bytes.fromhex(self.parent_container.open_file(i).read().decode())
                except ValueError:
                    continue
            elif self.parent_container.get_file_size(i) == 16:
                key = self.parent_container.open_file(i).read()
            else:
                continue

            block_dec = f.decrypt_block(block,key)
            if block_dec[:7] in expected_magic:
                LOGGER.info("Found key: %s", key.hex())
                return key

        # Check if the disc decrypted with a debug key
        debug_key = '67c0758cf4996fef7e88f90cc6959d66'
        block_dec = f.decrypt_block(block, bytes.fromhex(debug_key))
        if block_dec[:7] in expected_magic:
            LOGGER.info("Found key: %s", debug_key)
            return bytes.fromhex(debug_key)

        # Check the key db if it exists
        db_file = (pathlib.Path(__file__).parent) / "keys.db"
        if not db_file.exists():
            LOGGER.warning("Could not find key db. Disc will not be decrypted!")
            return

        db = sqlite3.connect(db_file)
        c = db.cursor()
        keys = c.execute('SELECT * FROM keys WHERE size = ?', [str(self.fp.length())]).fetchall()
        for key in keys:
            block_dec = f.decrypt_block(block, key[-1])
            if block_dec[:7] in expected_magic:
                LOGGER.info("Found key: %s", key[-1].hex())
                return key[-1]

        LOGGER.warning("Could not find key for disc. Disc will not be decrypted!")
        return

    def open_file(self, file):
        if not self.disc_key:
            return super().open_file(file)

        for region in self.regions:
            if region.start <= file.inode.fp_offset < region.end:
                if region.encrypted:
                    io_class = functools.partial(DecryptedFileReader, disc_key=self.disc_key)
                    return super().open_file(file, io_class)
                else:
                    return super().open_file(file)
        return super().open_file(file)
