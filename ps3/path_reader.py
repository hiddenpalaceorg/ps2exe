import collections
import functools
import logging
import pathlib
import sqlite3
import struct

from Crypto.Cipher import AES

from common.iso_path_reader.methods.pycdlib import PyCdLibPathReader
from utils.pycdlib.decrypted_file_io import DecryptedFileIO

LOGGER = logging.getLogger(__name__)


class DecryptedFileReader(DecryptedFileIO):
    def __init__(self, ino, logical_block_size, disc_key):
        super().__init__(ino, logical_block_size)
        self.disc_key = disc_key

    def decrypt_blocks(self, blocks):
        if not self.disc_key:
            return blocks

        decrypted = bytearray()
        start_pos = (self._fp.tell() // 2048) - (len(blocks) // 2048)

        for i in range(0, len(blocks), 2048):
            block = blocks[i:i+2048]
            pos = start_pos + (i // 2048)
            iv = bytearray(b'\x00' * 16)

            for j in range(16):
                iv[16 - j - 1] = (pos & 0xFF)
                pos >>= 8

            cipher = AES.new(self.disc_key, AES.MODE_CBC, bytes(iv))
            decrypted.extend(cipher.decrypt(block))

        return bytes(decrypted)


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

            f.disc_key = key
            block_dec = f.decrypt_blocks(block)
            if block_dec[:7] in expected_magic:
                LOGGER.info("Found key: %s", key.hex())
                return key

        # Check if the disc decrypted with a debug key
        debug_key = '67c0758cf4996fef7e88f90cc6959d66'
        f.disc_key = bytes.fromhex(debug_key)
        block_dec = f.decrypt_blocks(block)
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
            f.disc_key = key[-1]
            block_dec = f.decrypt_blocks(block)
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
