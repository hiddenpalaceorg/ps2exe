import collections
import os

from pycdlib import PyCdlib, pycdlibexception, headervd, inode
from pycdlib import udf as udfmod

allzero = b'\x00' * 2048

class PyCdlibUdf(PyCdlib):
    def _initialize(self):
        super()._initialize()
        self.pvd = None
        self.udf_tea = udfmod.TEAVolumeStructure()

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
            except pycdlibexception.PyCdlibInvalidISO:
                continue
            if anchor_tag.tag_ident != 2:
                continue
            anchor = udfmod.UDFAnchorVolumeStructure()
            anchor.parse(anchor_data, extent, anchor_tag)
            self.udf_anchors.append(anchor)

        if len(self.udf_anchors) < 2:
            raise pycdlibexception.PyCdlibInvalidISO('Expected at least 2 UDF Anchors, only saw %d' % (len(self.udf_anchors)))

        for anchor in self.udf_anchors[1:]:
            if self.udf_anchors[0] != anchor:
                raise pycdlibexception.PyCdlibInvalidISO('Anchor points do not match')

        # ECMA-167, Part 3, 8.4.2 says that the anchors identify the main
        # volume descriptor sequence, so look for it here.

        # Parse the Main Volume Descriptor Sequence.
        self.udf_main_descs = self._parse_udf_vol_descs(self.udf_anchors[0].main_vd)

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
        current_extent = self.udf_main_descs.partitions[0].part_start_location
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

        if desc_tag.tag_ident != 256:
            raise pycdlibexception.PyCdlibInvalidISO('UDF File Set Tag identifier not 256')

        self.udf_file_set.parse(partition_data[:self.logical_block_size],
                                current_extent, desc_tag)

        # OK, now look to see if we have a terminating descriptor
        current_extent += 1
        # FIXME: deal with running out of space on the Partition
        terminating_data = self._cdfp.read(self.logical_block_size)
        desc_tag = udfmod.UDFTag()
        desc_tag.parse(terminating_data,
                       current_extent - self.udf_main_descs.partitions[0].part_start_location)
        if desc_tag.tag_ident == 8:
            self.udf_file_set_terminator = udfmod.UDFTerminatingDescriptor()
            self.udf_file_set_terminator.parse(current_extent, desc_tag)

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
        fsd_start = self.udf_file_set.extent_location()
        self.udf_root = self._parse_udf_file_entry(fsd_start + self.udf_file_set.root_dir_icb.log_block_num,
                                                   self.udf_file_set.root_dir_icb,
                                                   None)

        udf_file_entries = collections.deque([self.udf_root])
        while udf_file_entries:
            udf_file_entry = udf_file_entries.popleft()

            if udf_file_entry is None:
                continue

            for desc in udf_file_entry.alloc_descs:
                abs_file_ident_extent = fsd_start + desc.log_block_num
                self._seek_to_extent(abs_file_ident_extent)
                self._cdfp.seek(desc.offset, 1)
                data = self._cdfp.read(desc.extent_length)
                offset = 0
                while offset < len(data):
                    current_extent = (abs_file_ident_extent * self.logical_block_size + offset) // self.logical_block_size

                    desc_tag = udfmod.UDFTag()
                    desc_tag.parse(data[offset:], current_extent - fsd_start)
                    if desc_tag.tag_ident != 257:
                        raise pycdlibexception.PyCdlibInvalidISO('UDF File Identifier Tag identifier not 257')
                    file_ident = udfmod.UDFFileIdentifierDescriptor()
                    offset += file_ident.parse(data[offset:],
                                               current_extent,
                                               desc_tag,
                                               udf_file_entry)
                    if file_ident.is_parent():
                        # For a parent, no further work to do.
                        udf_file_entry.track_file_ident_desc(file_ident)
                        continue

                    abs_file_entry_extent = fsd_start + file_ident.icb.log_block_num
                    next_entry = self._parse_udf_file_entry(abs_file_entry_extent,
                                                            file_ident.icb,
                                                            udf_file_entry)

                    # For a non-parent, we delay adding this to the list of
                    # fi_descs until after we check whether this is a valid
                    # entry or not.
                    udf_file_entry.track_file_ident_desc(file_ident)

                    if next_entry is None:
                        if file_ident.is_dir():
                            raise pycdlibexception.PyCdlibInvalidISO('Empty UDF File Entry for directories are not allowed')

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