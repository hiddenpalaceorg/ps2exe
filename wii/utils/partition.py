"""
wiiod.partition
~~~~~~~~~~~~~~~

Access a crypted Wii partition and locates the bootloader, the DOL
executable and the filesystem.

This file is part of wiiodfs.

wiiodfs is free software: you can redistribute it and/or modify it under the
terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.

wiiodfs is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
wiiodfs.  If not, see <http://www.gnu.org/licenses/>.
"""
import os
from functools import lru_cache

from Crypto.Cipher import AES

import struct
import logging

LOGGER = logging.getLogger(__name__)

# Some magic locations :)
TITLE_KEY_OFFSET = 0x1BF
TITLE_ID_OFFSET = 0x1DC
DATA_START_OFFSET = 0x2B8
DATA_SIZE_OFFSET = 0x2BC

MASTER_KEYS = {
    "rvl-common": b"\xeb\xe4\x2a\x22\x5e\x85\x93\xe4\x48\xd9\xc5\x45\x73\x81\xaa\xf7",
    "rvl-korean": b"\x63\xb8\x2b\xb4\xf4\x61\x4e\x2e\x13\xf2\xfe\xfb\xba\x4c\x9b\x7e",
    "wup-common": b"\xD7\xB0\x04\x02\x65\x9B\xA2\xAB\xD2\xCB\x0D\xB2\x7F\xA2\xB6\x56",
    "rvt-debug": b"\xA1\x60\x4A\x6A\x71\x23\xB5\x29\xAE\x8B\xEC\x32\xC8\x16\xFC\xAA",
    "rvt-korean": b"\x67\x45\x8B\x6B\xC6\x23\x7B\x32\x69\x98\x3C\x64\x73\x48\x33\x66",
    "cat-common": b"\x2F\x5C\x1B\x29\x44\xE7\xFD\x6F\xC3\x97\x96\x4B\x05\x76\x91\xFA",
}

# Size of a disc cluster and data stored by cluster
CLUSTER_SIZE = 0x8000
CLUSTER_DATA_SIZE = 0x7C00

# Number of decrypted clusters stored in the LRU cache
CLUSTER_CACHE_SIZE = 128


class Partition(object):
    pos = 0

    def __init__(self, disc, part_infos):
        """
        Initializes a partition object from a wiiod.disc.Disc and partition
        informations (of type wiiod.disc.PartitionInfos).
        """
        self.disc = disc
        self.disc_infos = part_infos

        self._read_header()

    def seek(self, pos, whence=os.SEEK_SET):
        if whence == os.SEEK_SET:
            self.pos = pos
        elif whence == os.SEEK_CUR:
            self.pos += pos
        elif whence == os.SEEK_END:
            self.pos = self.data_size + pos

    def read(self, size):
        ret = self.read_from_offset(self.pos, size)
        self.pos += size
        return ret

    def read_raw(self, offset, size):
        """
        Read raw non-decrypted data relative to the partition start.
        """
        return self.disc.read(self.disc_infos.offset + offset, size)

    def read_from_offset(self, offset, size):
        """
        Reads decrypted data from the partition.
        """
        if not self.decryption_key:
            return self.read_raw(self.data_start + offset, size)

        data = b''
        while size > 0:
            cluster_data = self.read_cluster(offset // CLUSTER_DATA_SIZE)

            start_off = offset % CLUSTER_DATA_SIZE
            last_off = min(start_off + size, CLUSTER_DATA_SIZE)
            read_size = last_off - start_off

            data += cluster_data[start_off:last_off]

            offset += read_size
            size -= read_size
        return data

    @lru_cache(maxsize=CLUSTER_CACHE_SIZE)
    def read_cluster(self, idx):
        """
        Reads and decrypts a data cluster from the disc. Will often be
        cached to avoid redecrypting.
        """
        raw_cluster = self.read_raw(self.data_start + idx * CLUSTER_SIZE,
                                    CLUSTER_SIZE)
        if self.decryption_key:
            iv = raw_cluster[0x3D0:0x3E0]
            aes = AES.new(self.decryption_key, AES.MODE_CBC, iv)
            return aes.decrypt(raw_cluster[0x400:])
        return raw_cluster

    def _read_header(self):
        """
        Reads the partition header to get informations like the title key and
        the partition data offset/size.
        """
        header = self.read_raw(0, 1024)

        encrypted_title_key = header[TITLE_KEY_OFFSET:TITLE_KEY_OFFSET + 0x10]
        title_id = header[TITLE_ID_OFFSET:TITLE_ID_OFFSET + 0x8]

        self.data_start = header[DATA_START_OFFSET:DATA_START_OFFSET + 4]
        self.data_start = struct.unpack(">L", self.data_start)[0]
        self.data_start *= 4

        self.data_size = header[DATA_SIZE_OFFSET:DATA_SIZE_OFFSET + 4]
        self.data_size = struct.unpack(">L", self.data_size)[0]
        self.data_size *= 4

        self.decryption_key = None
        self.master_key = self._get_master_key(encrypted_title_key, title_id)
        LOGGER.info("Found master key %s", self.master_key)

    def _get_master_key(self, encrypted_key, title_id):
        # First check if the partition is even decrypted at all
        part_header = self.read_from_offset(0x18, 4)
        if part_header == b"\x5D\x1C\x9E\xA3":
            return None

        for key_type, key in MASTER_KEYS.items():
            self.read_cluster.cache_clear()
            self.decryption_key = self._decrypt_key(encrypted_key, title_id, key)
            part_header = self.read_from_offset(0x18, 4)
            if part_header == b"\x5D\x1C\x9E\xA3":
                return key_type
        raise ValueError("Could not find master key")

    def _decrypt_key(self, key, title_id, master_key):
        """
        Decrypts the title decryption key using the encrypted key and the
        title id.
        """
        iv = title_id + 8 * b"\x00"
        aes = AES.new(master_key, AES.MODE_CBC, iv)
        return aes.decrypt(key)
