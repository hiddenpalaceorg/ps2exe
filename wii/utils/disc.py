"""
wiiod.disc
~~~~~~~~~~

Disc image handling utilities: access disc metadatas like game description,
maker code and region, and access raw crypted disc partitions.

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

import collections
import struct

from utils.files import get_file_size

VGTABLE_OFFSET = 0x40000
NUMBER_OF_VG = 4

# Partition information. Really simple struct with only four fields.
PartitionInfos = collections.namedtuple('PartitionInfos', ' '.join((
    'volume_group',
    'index',
    'offset',
    'type'
)))

class Disc(object):
    def __init__(self, fp):
        """
        Initializes a disc object from an open file descriptor.
        """
        self.fp = fp
        (self.game_id, self.disc_num, self.disc_version,
         self.audio_streaming, self.streaming_buffer_size,
         self.wii_magic, self.title, self.disable_hash_verification,
         self.disable_encryption) = struct.unpack("6sbb?b14xI4x64s??", self.read(0, 0x62))
        self.title = self.title.rstrip(b'\x00')
        self._read_vg_table()

    def read(self, offset, size):
        """
        Reads data from an offset and a size.
        """
        if get_file_size(self.fp) < offset:
            raise ValueError("Out of range")
        self.fp.seek(offset)
        return self.fp.read(size)

    @property
    def partitions(self):
        """
        Iterates on all the partitions
        """
        for vg in self.volume_groups:
            for part in vg:
                yield part

    def _read_vg_table(self):
        """
        Reads the volume groups table, and the partitions table from the
        four volume groups.
        """
        self.volume_groups = []
        for i in range(NUMBER_OF_VG):
            tup = struct.unpack('>LL', self.read(VGTABLE_OFFSET + 8 * i, 8))
            number_of_partitions, parttable_offset = tup

            self.volume_groups.append([])
            self._read_partition_table(i, parttable_offset * 4,
                                       number_of_partitions)

    def _read_partition_table(self, volume_group, offset, number_of_parts):
        """
        Reads a partition table from the given informations, filling the
        provided volume group.
        """
        for i in range(number_of_parts):
            tup = struct.unpack('>LL', self.read(offset + 8 * i, 8))
            part_offset, part_type = tup

            infos = (volume_group, i, part_offset * 4, part_type)
            self.volume_groups[volume_group].append(PartitionInfos(*infos))
