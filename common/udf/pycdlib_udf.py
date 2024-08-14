import collections
import functools
import os
import struct

from pycdlib import PyCdlib, pycdlibexception, headervd, inode, pycdlib
from pycdlib import udf as udfmod

allzero = b'\x00' * 2048

class PyCdlibUdf(PyCdlib):
    vat = None

    def _initialize(self):
        super()._initialize()
        self.pvd = None
        self.udf_tea = udfmod.TEAVolumeStructure()
        self.vat = None

    def _parse_volume_descriptors(self):
        try:
            return super()._parse_volume_descriptors()
        except pycdlibexception.PyCdlibInvalidISO:
            if not self.pvds and not self._has_udf:
                raise

    def _parse_udf_descriptors(self):
        # type: () -> None
        '''
        An internal method to parse the UDF descriptors on the ISO.  This should
        only be called if it the ISO has a valid UDF Volume Recognition Sequence
        at the beginning of the ISO.
        Parameters:
         None.
        Returns:
         Nothing.
        '''
        # Parse the anchors.  According to ECMA-167, Part 3, 8.4.2.1, there
        # must be anchors recorded in at least two of the three extent locations
        # 256, N-256, and N, where N is the total number of extents on the disc.
        # We'll preserve all 3 if they exist, with a minimum of two for a valid
        # disc.
        self._cdfp.seek(0, os.SEEK_END)
        last_extent = (self._cdfp.tell() // self.logical_block_size) - 1
        anchor_locations = [256, last_extent - 256, last_extent]
        for loc in anchor_locations:
            self._seek_to_extent(loc)
            extent = self._cdfp.tell() // self.logical_block_size
            anchor_data = self._cdfp.read(self.logical_block_size)
            anchor_tag = udfmod.UDFTag()
            try:
                anchor_tag.parse(anchor_data, extent)
            except (pycdlibexception.PyCdlibInvalidISO, struct.error):
                continue
            if anchor_tag.tag_ident != 2:
                continue
            anchor = udfmod.UDFAnchorVolumeStructure()
            anchor.parse(anchor_data, extent, anchor_tag)
            self.udf_anchors.append(anchor)

        # ECMA-167, Part 3, 8.4.2 says that the anchors identify the main
        # volume descriptor sequence, so look for it here.

        # Parse the Main Volume Descriptor Sequence.
        self.udf_main_descs = self._parse_udf_vol_descs(self.udf_anchors[0].main_vd)
        for part_id, pmap in enumerate(self.udf_main_descs.logical_volumes[0].partition_maps):
            if isinstance(pmap, udfmod.UDFType2PartitionMap):
                part_type = pmap.part_ident[3:26].rstrip(b'\x00')
                if part_type == b"*UDF Virtual Partition":
                    type2map = UDFVirtualPartitionMap()
                    type2map.parse(pmap.part_ident)
                    self.udf_main_descs.logical_volumes[0].partition_maps[part_id] = type2map
                elif part_type == b"*UDF Metadata Partition":
                    type2map = UDFMetadataPartitionMap()
                    type2map.parse(pmap.part_ident)
                    self.udf_main_descs.logical_volumes[0].partition_maps[part_id] = type2map

        # ECMA-167, Part 3, 8.4.2 and 8.4.2.2 says that the anchors *may*
        # identify a reserve volume descriptor sequence.  10.2.3 says that
        # a reserve volume sequence is identified if the length is > 0.

        if self.udf_anchors[0].reserve_vd.extent_length > 0:
            # Parse the Reserve Volume Descriptor Sequence.
            self.udf_reserve_descs = self._parse_udf_vol_descs(self.udf_anchors[0].main_vd)

        # ECMA-167, Part 3, 10.6.12 says that the integrity sequence extent
        # only exists if the length is > 0.
        if self.udf_main_descs.logical_volumes[0].integrity_sequence.extent_length > 0:
            # Parse the Logical Volume Integrity Sequence.
            self._seek_to_extent(self.udf_main_descs.logical_volumes[0].integrity_sequence.extent_location)
            integrity_data = self._cdfp.read(self.udf_main_descs.logical_volumes[0].integrity_sequence.extent_length)

            offset = 0
            current_extent = self.udf_main_descs.logical_volumes[0].integrity_sequence.extent_location
            desc_tag = udfmod.UDFTag()
            desc_tag.parse(integrity_data[offset:], current_extent)
            if desc_tag.tag_ident != 9:
                raise pycdlibexception.PyCdlibInvalidISO('UDF Volume Integrity Tag identifier not 9')
            self.udf_logical_volume_integrity = udfmod.UDFLogicalVolumeIntegrityDescriptor()
            self.udf_logical_volume_integrity.parse(integrity_data[offset:offset + 512],
                                                    current_extent, desc_tag)

            # According to the TR-071, 2.3, the end of a logical volume integrity
            # can be one of:
            # 1.  An all zero extent
            # 2.  A terminator
            # 3.  The end of the size of the integrity sequence extent (in our case,
            # logical_volume.integrity_sequence_length).

            # FIXME: handle a terminator

            offset += self.logical_block_size
            if len(integrity_data) >= (offset + self.logical_block_size):
                # OK, there is more data to read in the integrity sequence, so try
                # to parse it here.
                current_extent += 1
                if integrity_data[offset:offset + self.logical_block_size] != allzero:
                    desc_tag = udfmod.UDFTag()
                    desc_tag.parse(integrity_data[offset:], current_extent)
                    if desc_tag.tag_ident != 8:
                        raise pycdlibexception.PyCdlibInvalidISO('UDF Logical Volume Integrity Terminator Tag identifier not 8')
                    self.udf_logical_volume_integrity_terminator = udfmod.UDFTerminatingDescriptor()
                    self.udf_logical_volume_integrity_terminator.parse(current_extent,
                                                                       desc_tag)

        # FIXME: It looks like there can be something called a "sparable partition map" at this point in the UDF.  We may need to handle that.

        # FIXME: It looks like there can be something called a "virtual paritition map" at this point in the UDF.  We may need to handle that.

        # Now start looking at the partition.  It can optionally start with a
        # Space Bitmap Descriptor; after that is the File Set Descriptor.  The
        # sequence may optionally be terminated by a UDF Terminating Descriptor.
        part_start = self.udf_main_descs.partitions[0].part_start_location
        current_extent = part_start + self.udf_main_descs.logical_volumes[0].logical_volume_contents_use.log_block_num
        self.root_relative_location = part_start
        self._seek_to_extent(current_extent)

        partition_data = self._cdfp.read(self.logical_block_size)

        # FIXME: deal with running out of space on the Partition

        desc_tag = udfmod.UDFTag()
        desc_tag.parse(partition_data[:self.logical_block_size], 0)
        if desc_tag.tag_ident == 261:
            file_entry = udfmod.UDFFileEntry()
            file_entry.parse(partition_data, current_extent, None, desc_tag)
            part_start = self.udf_main_descs.partitions[0].part_start_location
            desc = file_entry.alloc_descs[0]
            abs_file_ident_extent = part_start + desc.log_block_num
            self._seek_to_extent(abs_file_ident_extent)
            self._cdfp.seek(desc.offset, 1)
            partition_data = self._cdfp.read(self.logical_block_size)
            current_extent = abs_file_ident_extent
            desc_tag = udfmod.UDFTag()
            desc_tag.parse(partition_data[:self.logical_block_size], 0)

        if desc_tag.tag_ident == 264:
            # OK, this is a Space Bitmap Descriptor; parse it
            self.udf_space_bitmap_desc = udfmod.UDFSpaceBitmapDescriptor()
            self.udf_space_bitmap_desc.parse(partition_data, current_extent,
                                             desc_tag)

            # FIXME: deal with running out of space on the Partition
            partition_data = self._cdfp.read(self.logical_block_size)
            current_extent += 1
            desc_tag = udfmod.UDFTag()
            desc_tag.parse(partition_data[:self.logical_block_size], 0)

        if desc_tag.tag_ident == 266:
            file_entry = UDFExtendedFileEntry()
            file_entry.parse(partition_data, current_extent, None, desc_tag)
            part_start = self.udf_main_descs.partitions[0].part_start_location
            desc = file_entry.alloc_descs[0]
            if not isinstance(desc, udfmod.UDFInlineAD):
                abs_file_ident_extent = part_start + desc.log_block_num
                self._seek_to_extent(abs_file_ident_extent)
                self._cdfp.seek(desc.offset, 1)
                partition_data = self._cdfp.read(self.logical_block_size)
                current_extent = abs_file_ident_extent
                desc_tag = udfmod.UDFTag()
                desc_tag.parse(partition_data[:self.logical_block_size], 0)

        if isinstance(self.udf_main_descs.logical_volumes[0].partition_maps[-1], UDFVirtualPartitionMap):
            # Try to find a VAT. They are supposed to be at the last extent, but could be earlier
            pmap = self.udf_main_descs.logical_volumes[0].partition_maps[-1]
            part_extent = next(part for part in self.udf_main_descs.partitions if part.part_num == pmap.part_num).part_num
            for block in reversed(range(part_extent, last_extent+1)):
                self._seek_to_extent(block)
                partition_data = self._cdfp.read(self.logical_block_size)
                desc_tag = udfmod.UDFTag()
                try:
                    desc_tag.parse(partition_data[:self.logical_block_size], 0)
                except:
                    continue
                if desc_tag.tag_ident == 261:
                    file_entry = udfmod.UDFFileEntry()
                    file_entry.parse(partition_data, block, None, desc_tag)
                    desc = file_entry.alloc_descs[0]
                    part_start = self.udf_main_descs.partitions[0].part_start_location
                    if isinstance(desc, udfmod.UDFInlineAD):
                        abs_file_ident_extent = desc.log_block_num
                    else:
                        abs_file_ident_extent = part_start + desc.log_block_num
                    self._seek_to_extent(abs_file_ident_extent)
                    self._cdfp.seek(desc.offset, 1)
                    partition_data = self._cdfp.read(file_entry.info_len)
                    self.vat = UDFVirtualAllocationTable()
                    self.vat.parse(partition_data, file_entry.info_len)
                    fsd_extent = self.vat.vat_entries[0] + part_start
                    self.root_relative_location = fsd_extent
                    self._seek_to_extent(fsd_extent)
                    partition_data = self._cdfp.read(self.logical_block_size)
                    current_extent = fsd_extent
                    desc_tag = udfmod.UDFTag()
                    desc_tag.parse(partition_data[:self.logical_block_size], 0)
                    break

        if isinstance(self.udf_main_descs.logical_volumes[0].partition_maps[-1], UDFMetadataPartitionMap):
            # load the metadata file
            pmap = self.udf_main_descs.logical_volumes[0].partition_maps[-1]
            part_start = self.udf_main_descs.partitions[pmap.part_num].part_start_location
            metadata_file_extent = part_start + pmap.metadata_file_location
            icb = udfmod.UDFInlineAD()
            icb.parse(2048, pmap.metadata_file_location, 0)
            metadata_file = self._parse_udf_file_entry(
                metadata_file_extent, icb, None
            )
            fsd_extent = metadata_file.alloc_descs[0].log_block_num + part_start
            self.root_relative_location = fsd_extent
            self._seek_to_extent(fsd_extent)
            partition_data = self._cdfp.read(self.logical_block_size)
            current_extent = fsd_extent
            desc_tag = udfmod.UDFTag()
            desc_tag.parse(partition_data[:self.logical_block_size], 0)


        for anchor in self.udf_anchors[1:]:
            if self.udf_anchors[0] != anchor:
                pycdlib._logger.warning('UDF anchor points do not match')

        if desc_tag.tag_ident != 256:
            raise pycdlibexception.PyCdlibInvalidISO('UDF File Set Tag identifier not 256')

        self.udf_file_set = UDFFileSetDescriptor()
        self.udf_file_set.parse(partition_data[:self.logical_block_size],
                                current_extent, desc_tag)

        # OK, now look to see if we have a terminating descriptor
        current_extent += 1
        # FIXME: deal with running out of space on the Partition
        terminating_data = self._cdfp.read(self.logical_block_size)
        try:
            desc_tag = udfmod.UDFTag()
            desc_tag.parse(terminating_data,
                           current_extent - self.udf_main_descs.partitions[0].part_start_location)
            if desc_tag.tag_ident == 8:
                self.udf_file_set_terminator = udfmod.UDFTerminatingDescriptor()
                self.udf_file_set_terminator.parse(current_extent, desc_tag)
        except pycdlibexception.PyCdlibInvalidISO:
            pass

    def _walk_udf_directories(self, extent_to_inode):
        # type: (Dict[int, inode.Inode]) -> None
        """
        An internal method to walk a UDF filesystem and add all the metadata to
        this object.

        Parameters:
         extent_to_inode - A map from extent numbers to Inodes.
        Returns:
         Nothing.
        """
        part_start = self.udf_main_descs.partitions[0].part_start_location
        self.udf_root = self._parse_udf_file_entry(self.root_relative_location + self.udf_file_set.root_dir_icb.log_block_num,
                                                   self.udf_file_set.root_dir_icb,
                                                   None)

        udf_file_entries = collections.deque([self.udf_root])
        while udf_file_entries:
            udf_file_entry = udf_file_entries.popleft()

            if udf_file_entry is None:
                continue

            data = b""
            for desc in udf_file_entry.alloc_descs:
                if isinstance(desc, udfmod.UDFInlineAD):
                    abs_file_ident_extent = desc.log_block_num
                elif self.vat:
                    part_start = self.udf_main_descs.partitions[0].part_start_location
                    if len(self.vat.vat_entries) >= desc.log_block_num:
                        abs_file_ident_extent = self.vat.vat_entries[desc.log_block_num] + part_start
                    else:
                        abs_file_ident_extent = desc.log_block_num + part_start
                else:
                    abs_file_ident_extent = self.root_relative_location + desc.log_block_num
                self._seek_to_extent(abs_file_ident_extent)
                self._cdfp.seek(desc.offset, 1)
                data += self._cdfp.read(desc.extent_length)
            offset = 0
            while offset < len(data):
                if data[offset:] == b"\x00" * len(data[offset:]):
                    offset = len(data)
                    continue
                current_extent = (abs_file_ident_extent * self.logical_block_size + offset) // self.logical_block_size

                desc_tag = udfmod.UDFTag()
                desc_tag.parse(data[offset:], current_extent - self.root_relative_location)
                if desc_tag.tag_ident != 257:
                    raise pycdlibexception.PyCdlibInvalidISO('UDF File Identifier Tag identifier not 257')
                file_ident = UDFFileIdentifierDescriptor()
                offset += file_ident.parse(data[offset:],
                                           current_extent,
                                           desc_tag,
                                           udf_file_entry)
                if file_ident.is_parent():
                    # For a parent, no further work to do.
                    udf_file_entry.track_file_ident_desc(file_ident)
                    continue

                if isinstance(file_ident.icb, udfmod.UDFInlineAD):
                    abs_file_entry_extent = file_ident.icb.log_block_num
                elif self.vat and len(self.vat.vat_entries) >= file_ident.icb.log_block_num:
                    part_start = self.udf_main_descs.partitions[0].part_start_location
                    abs_file_entry_extent = self.vat.vat_entries[file_ident.icb.log_block_num] + part_start
                else:
                    abs_file_entry_extent = self.root_relative_location + file_ident.icb.log_block_num
                next_entry = self._parse_udf_file_entry(abs_file_entry_extent,
                                                        file_ident.icb,
                                                        udf_file_entry)

                # For a non-parent, we delay adding this to the list of
                # fi_descs until after we check whether this is a valid
                # entry or not.
                udf_file_entry.track_file_ident_desc(file_ident)

                if next_entry is None:
                    # If the next_entry is None, then we just skip the
                    # rest of the code dealing with the entry and the
                    # Inode.
                    continue

                file_ident.file_entry = next_entry
                next_entry.file_ident = file_ident

                if file_ident.is_dir():
                    udf_file_entries.append(next_entry)
                else:
                    if next_entry.get_data_length() > 0:
                        abs_file_data_extent = part_start + next_entry.alloc_descs[0].log_block_num
                    else:
                        abs_file_data_extent = 0
                    if self.eltorito_boot_catalog is not None and abs_file_data_extent == self.eltorito_boot_catalog.extent_location():
                        self.eltorito_boot_catalog.add_dirrecord(next_entry)
                    else:
                        if abs_file_data_extent in extent_to_inode:
                            ino = extent_to_inode[abs_file_data_extent]
                        else:
                            ino = inode.Inode()
                            ino.parse(abs_file_data_extent,
                                      next_entry.get_data_length(),
                                      self._cdfp, self.logical_block_size)
                            extent_to_inode[abs_file_data_extent] = ino
                            self.inodes.append(ino)

                        ino.linked_records.append((next_entry, False))
                        next_entry.inode = ino

    def _open_fp(self, fp):
        if hasattr(fp, 'mode') and 'b' not in fp.mode:
            raise pycdlibexception.PyCdlibInvalidInput("The file to open must be in binary mode (add 'b' to the open flags)")

        self._cdfp = fp
        self._parse_volume_descriptors()

        extent_to_inode = {}  # type: Dict[int, inode.Inode]
        # Look to see if this is a UDF volume.  It is one if we have a UDF BEA,
        # UDF NSR, and UDF TEA, in which case we parse the UDF descriptors and
        # walk the filesystem.
        if self._has_udf:
            self._parse_udf_descriptors()
            self._walk_udf_directories(extent_to_inode)

        # Now we look for the 'version' volume descriptor, common on ISOs made
        # with genisoimage or mkisofs.  This volume descriptor doesn't have any
        # specification, but from code inspection, it is either a completely
        # zero extent, or starts with 'MKI'.  Further, it starts directly after
        # the VDST, or directly after the UDF recognition sequence (if this is
        # a UDF ISO).  Thus, we go looking for it at those places, and add it
        # if we find it there.
        version_vd_extent = self.udf_teas[0].extent_location() + 1
        version_vd = headervd.VersionVolumeDescriptor()
        self._seek_to_extent(version_vd_extent)
        if version_vd.parse(self._cdfp.read(self.logical_block_size), version_vd_extent):
            self.version_vd = version_vd

        self._initialized = True

    def _parse_udf_file_entry(self, abs_file_entry_extent, icb, parent):
        # type: (int, udfmod.UDFLongAD, Optional[udfmod.UDFFileEntry]) -> Optional[udfmod.UDFFileEntry]
        """
        An internal method to parse a single UDF File Entry and return the
        corresponding object.

        Parameters:
         abs_file_entry_extent - The extent number the file entry starts at.
         icb - The ICB object for the data.
         parent - The parent of the UDF File Entry.
        Returns:
         A UDF File Entry object corresponding to the on-disk File Entry.
        """
        self._seek_to_extent(abs_file_entry_extent)
        icbdata = self._cdfp.read(icb.extent_length)

        if all(v == 0 for v in bytearray(icbdata)):
            # We have seen ISOs in the wild (Windows 2008 Datacenter Enterprise
            # Standard SP2 x86 DVD) where the UDF File Identifier points to a
            # UDF File Entry of all zeros.  In those cases, we just keep the
            # File Identifier, and keep the UDF File Entry blank.
            return None

        desc_tag = udfmod.UDFTag()
        desc_tag.parse(icbdata, icb.log_block_num)
        if desc_tag.tag_ident == 261:
            file_entry = udfmod.UDFFileEntry()
            file_entry.parse(icbdata, abs_file_entry_extent, parent, desc_tag)
        elif desc_tag.tag_ident == 266:
            file_entry = UDFExtendedFileEntry()
            file_entry.parse(icbdata, abs_file_entry_extent, parent, desc_tag)
            # file_entry.parent = parent
        else:
            raise pycdlibexception.PyCdlibInvalidISO('UDF File Entry Tag identifier not 261 or 266')



        return file_entry


class UDFExtendedFileEntry(udfmod.UDFExtendedFileEntry):

    def __new__(cls, *args, **kwargs):
        cls.__slots__ += ('parent', 'fi_descs',)
        return udfmod.UDFExtendedFileEntry.__new__(cls, *args, **kwargs)

    def __init__(self):
        super().__init__()
        self.alloc_descs = []
        self.fi_descs = []
        self._initialized = False
        self.parent = None
        self.hidden = False
        self.file_ident = None
        self.inode = None
        self.new_extent_loc = -1

    def parse(self, data, extent, parent, desc_tag):
        super().parse(data, extent, desc_tag)
        self.parent = parent

    # Hack, wrap UDFExtendedFileEntry calls around UDFFileEntry
    def __getattr__(self, item):
        if callable(getattr(udfmod.UDFFileEntry, item)):
            return functools.partial(getattr(udfmod.UDFFileEntry, item), self)
        return getattr(udfmod.UDFFileEntry, item)


class UDFVirtualPartitionMap(udfmod.UDFType1PartitionMap):
    """A class representing a UDF Type 2 Virtual Partition Map (UDF 2.60, 2.2.8)."""
    __slots__ = ('_initialized', 'vol_seqnum', 'part_num')

    FMT = '<HB23s8sHH24s'

    def parse(self, data):
        # type: (bytes) -> None
        """
        Parse the passed in data into a UDF Type 2 Virtual Partition Map

        Parameters:
         data - The data to parse.
        Returns:
         Nothing.
        """
        if self._initialized:
            raise pycdlibexception.PyCdlibInternalError('UDF Type 2 Virtual Partition Map already initialized')

        (unused1, part_type_flags, part_type_id, part_type_id_suffix, self.vol_seqnum,
         self.part_num, unused2) = struct.unpack_from(self.FMT, data, 0)

        if part_type_id.rstrip(b'\x00') != b"*UDF Virtual Partition":
            raise pycdlibexception.PyCdlibInvalidISO('UDF Type 2 Virtual Partition Map Ident not "UDF Virtual Partition"')

        self._initialized = True


class UDFMetadataPartitionMap(udfmod.UDFType1PartitionMap):
    """A class representing a UDF Type 2 Metadata Partition Map (UDF 2.60, 2.2.10)."""
    __slots__ = ('_initialized', 'vol_seqnum', 'part_num',
                 'metadata_file_location', 'metadata_mirror_file_location',
                 'metadata_bitmap_file_location', 'alloc_size', 'align_size', 'flags')

    FMT = '<HB23s8sHHIIIIHB5s'

    def parse(self, data):
        # type: (bytes) -> None
        """
        Parse the passed in data into a UDF Type 2 Metadata Partition Map

        Parameters:
         data - The data to parse.
        Returns:
         Nothing.
        """
        if self._initialized:
            raise pycdlibexception.PyCdlibInternalError('UDF Type 2 Virtual Partition Map already initialized')

        (unused1, part_type_flags, part_type_id, part_type_id_suffix,
         self.vol_seqnum, self.part_num, self.metadata_file_location,
         self.metadata_mirror_file_location, self.metadata_bitmap_file_location,
         self.alloc_size, self.align_size, self.flags, unused2) = struct.unpack_from(self.FMT, data, 0)

        if part_type_id.rstrip(b'\x00') != b"*UDF Metadata Partition":
            raise pycdlibexception.PyCdlibInvalidISO('UDF Type 2 Metadata Partition Map Ident not "UDF Metadata Partition"')

        self._initialized = True


class UDFVirtualAllocationTable:
    """A class representing a UDF Virtual Allocation Table (UDF 2.60 2.2.11)."""

    __slots__ = ('_initialized', 'logical_volume_identifier', 'prev_vat_loc',
                 'length_impl_use', 'num_files', 'num_dirs',
                 'min_udf_read_revision', 'min_udf_write_revision',
                 'max_udf_write_revision', 'impl_use', 'vat_entries')

    FMT = '<HH128sIIIHHHH'

    def __init__(self):
        self._initialized = False
        self.vat_entries = []

    def parse(self, data, info_len):

        if self._initialized:
            raise pycdlibexception.PyCdlibInternalError(
                'UDF Virtual Allocation Table already initialized')

        (header_length, self.length_impl_use, self.logical_volume_identifier, self.prev_vat_loc,
         self.num_files, self.num_dirs, self.min_udf_read_revision, self.min_udf_write_revision,
         self.max_udf_write_revision, unused) = struct.unpack_from(self.FMT, data, 0)

        self.impl_use = data[152:152+self.length_impl_use]

        num_vat_entries = (info_len - header_length) // 4

        offset = header_length
        for vat_entry_num in range(0, num_vat_entries):
            vat_entry = struct.unpack('<I', data[offset:offset+4])[0]
            if vat_entry != 0xFFFFFFFF:
                self.vat_entries.append(vat_entry)
            offset += 4
        self._initialized = True


class UDFFileSetDescriptor(udfmod.UDFFileSetDescriptor):
    def parse(self, data, extent, desc_tag):
        """Same as parent class but without the DVD Read-only video restriction"""
        if self._initialized:
            raise pycdlibexception.PyCdlibInternalError('UDF File Set Descriptor already initialized')

        (tag_unused, recording_date, interchange_level, max_interchange_level,
         char_set_list, max_char_set_list, self.file_set_num, file_set_desc_num,
         log_vol_char_set, self.log_vol_ident, file_set_char_set,
         self.file_set_ident, self.copyright_file_ident,
         self.abstract_file_ident, root_dir_icb, domain_ident, next_extent,
         system_stream_dir_icb, reserved_unused) = struct.unpack_from(self.FMT, data, 0)

        self.desc_tag = desc_tag

        self.recording_date = udfmod.UDFTimestamp()
        self.recording_date.parse(recording_date)

        self.log_vol_char_set = udfmod.UDFCharspec()
        self.log_vol_char_set.parse(log_vol_char_set)

        self.file_set_char_set = udfmod.UDFCharspec()
        self.file_set_char_set.parse(file_set_char_set)

        self.domain_ident = udfmod.UDFEntityID()
        self.domain_ident.parse(domain_ident)
        if self.domain_ident.identifier[:19] != b'*OSTA UDF Compliant':
            raise pycdlibexception.PyCdlibInvalidISO("File Set Descriptor Identifier not '*OSTA UDF Compliant'")

        self.root_dir_icb = udfmod.UDFLongAD()
        self.root_dir_icb.parse(root_dir_icb)

        self.next_extent = udfmod.UDFLongAD()
        self.next_extent.parse(next_extent)

        self.system_stream_dir_icb = udfmod.UDFLongAD()
        self.system_stream_dir_icb.parse(system_stream_dir_icb)

        self.orig_extent_loc = extent

        self._initialized = True


class UDFTimestamp(udfmod.UDFTimestamp):
    def parse(self, data):
        """Same as the parent but without erroring out on invalid timestamps"""
        if self._initialized:
            raise pycdlibexception.PyCdlibInternalError('UDF Timestamp already initialized')

        (tz, timetype, self.year, self.month, self.day, self.hour, self.minute,
         self.second, self.centiseconds, self.hundreds_microseconds,
         self.microseconds) = struct.unpack_from(self.FMT, data, 0)

        self.timetype = timetype >> 4

        def twos_comp(val, bits):
            # type: (int, int) -> int
            """Compute the 2's complement of int value val"""
            if (val & (1 << (bits - 1))) != 0:  # if sign bit is set e.g., 8bit: 128-255
                val = val - (1 << bits)  # compute negative value
            return val  # return positive value as is

        self.tz = twos_comp(((timetype & 0xf) << 8) | tz, 12)
        if self.tz < -1440 or self.tz > 1440:
            if self.tz != -2047:
                self.tz = -2047

        if self.year < 1 or self.year > 9999:
            self.year = None
        if self.month < 1 or self.month > 12:
            self.month = None
        if self.day < 1 or self.day > 31:
            self.day = None
        if self.hour < 0 or self.hour > 23:
            self.hour = None
        if self.minute < 0 or self.minute > 59:
            self.minute = None
        if self.second < 0 or self.second > 59:
            self.second = None

        self._initialized = True
udfmod.UDFTimestamp = UDFTimestamp


class UDFFileIdentifierDescriptor(udfmod.UDFFileIdentifierDescriptor):
    def parse(self, data, extent, desc_tag, parent):
        if self._initialized:
            raise pycdlibexception.PyCdlibInternalError('UDF File Identifier Descriptor already initialized')

        (tag_unused, file_version_num, self.file_characteristics,
         self.len_fi, icb, self.len_impl_use) = struct.unpack_from(self.FMT, data, 0)

        self.desc_tag = desc_tag

        if file_version_num != 1:
            raise pycdlibexception.PyCdlibInvalidISO('File Identifier Descriptor file version number not 1')

        if self.file_characteristics & 0x2:
            self.isdir = True

        if self.file_characteristics & 0x8:
            self.isparent = True

        self.icb = udfmod.UDFLongAD()
        self.icb.parse(icb)

        start = struct.calcsize(self.FMT)
        end = start + self.len_impl_use
        self.impl_use = data[start:end]

        start = end
        end = start + self.len_fi
        # The very first byte of the File Identifier describes whether this is
        # an 8-bit or 16-bit encoded string; this corresponds to whether we
        # encode with 'latin-1' or with 'utf-16_be'.  We save that off because
        # we have to write the correct thing out when we record.
        if not self.isparent:
            encoding = bytes(bytearray([data[start]]))
            if encoding == b'\x08':
                self.encoding = 'latin-1'
            elif encoding == b'\x10':
                self.encoding = 'utf-16_be'
            else:
                self.encoding = 'latin-1'

            start += 1

            self.fi = data[start:end]

        self.orig_extent_loc = extent

        self.parent = parent

        self._initialized = True

        return end + UDFFileIdentifierDescriptor.pad(end)
