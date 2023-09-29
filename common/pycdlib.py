"""
Modified versions of PyCdlib classes that support High Sierra format (a predecessor to ISO9660)
"""
import collections
import os
import struct
import pycdlib.udf as udfmod

from pycdlib import PyCdlib as _PyCdlib, pycdlibexception, path_table_record, headervd, utils, dates, inode
from pycdlib.headervd import PrimaryOrSupplementaryVD as _PrimaryOrSupplementaryVD
from pycdlib.headervd import VolumeDescriptorSetTerminator as _VolumeDescriptorSetTerminator
from pycdlib.dr import DirectoryRecord as _DirectoryRecord, XARecord
from pycdlib.pycdlib import _interchange_level_from_directory, _interchange_level_from_filename


class PyCdlib(_PyCdlib):
    is_hs = False

    def _parse_volume_descriptors(self):
        self._cdfp.seek(16 * 2048)
        while True:
            # All volume descriptors are exactly 2048 bytes long
            curr_extent = self._cdfp.tell() // 2048
            vd = self._cdfp.read(2048)
            if len(vd) != 2048:
                raise pycdlibexception.PyCdlibInvalidISO('Failed to read entire volume descriptor')
            (desc_type_iso, ident_iso, desc_type_hs, ident_hs) = struct.unpack_from('=B5s2xB5s', vd, 0)
            if desc_type_iso in (headervd.VOLUME_DESCRIPTOR_TYPE_PRIMARY,
                                 headervd.VOLUME_DESCRIPTOR_TYPE_SET_TERMINATOR,
                                 headervd.VOLUME_DESCRIPTOR_TYPE_BOOT_RECORD,
                                 headervd.VOLUME_DESCRIPTOR_TYPE_SUPPLEMENTARY) and ident_iso in (b'CD001', b'CDW02', b'BEA01', b'NSR02', b'NSR03', b'TEA01', b'BOOT2'):
                desc_type = desc_type_iso
                ident = ident_iso
            elif desc_type_hs in (headervd.VOLUME_DESCRIPTOR_TYPE_PRIMARY,
                                 headervd.VOLUME_DESCRIPTOR_TYPE_SET_TERMINATOR,
                                 headervd.VOLUME_DESCRIPTOR_TYPE_BOOT_RECORD,
                                 headervd.VOLUME_DESCRIPTOR_TYPE_SUPPLEMENTARY) and ident_hs == b'CDROM':
                desc_type = desc_type_hs
                ident = ident_hs
                self.is_hs = True
                vd = vd[8:] + b'\x00' * 8
            else:
                # We read the next extent, and it wasn't a descriptor.  Abort
                # the loop, remembering to back up the input file descriptor.
                self._cdfp.seek(-2048, os.SEEK_CUR)
                break
            if desc_type == headervd.VOLUME_DESCRIPTOR_TYPE_PRIMARY:
                pvd = PrimaryOrSupplementaryVD(headervd.VOLUME_DESCRIPTOR_TYPE_PRIMARY)
                pvd.parse(vd, ident, curr_extent)
                self.pvds.append(pvd)
            elif desc_type == headervd.VOLUME_DESCRIPTOR_TYPE_SET_TERMINATOR:
                vdst = VolumeDescriptorSetTerminator()
                vdst.parse(vd, curr_extent)
                self.vdsts.append(vdst)
            elif desc_type == headervd.VOLUME_DESCRIPTOR_TYPE_BOOT_RECORD:
                # Both an Ecma-119 Boot Record and a Ecma-TR 071 UDF-Bridge
                # Beginning Extended Area Descriptor have the first byte as 0,
                # so we can't tell which it is until we look at the next 5
                # bytes (Boot Record will have 'CD001', BEAD will have 'BEA01').
                if ident == b'CD001':
                    br = headervd.BootRecord()
                    br.parse(vd, curr_extent)
                    self.brs.append(br)
                elif ident == b'BEA01':
                    self._has_udf = True
                    udf_bea = udfmod.BEAVolumeStructure()
                    udf_bea.parse(vd, curr_extent)
                    self.udf_beas.append(udf_bea)
                elif ident in (b'NSR02', b'NSR03'):
                    self.udf_nsr.parse(vd, curr_extent)
                elif ident == b'TEA01':
                    udf_tea = udfmod.TEAVolumeStructure()
                    udf_tea.parse(vd, curr_extent)
                    self.udf_teas.append(udf_tea)
                elif ident == b'BOOT2':
                    udf_boot = udfmod.UDFBootDescriptor()
                    udf_boot.parse(vd, curr_extent)
                    self.udf_boots.append(udf_boot)
                else:
                    # This isn't really possible, since we would have aborted
                    # the loop above.
                    raise pycdlibexception.PyCdlibInvalidISO('Invalid volume identification type')
            elif desc_type == headervd.VOLUME_DESCRIPTOR_TYPE_SUPPLEMENTARY:
                svd = headervd.PrimaryOrSupplementaryVD(headervd.VOLUME_DESCRIPTOR_TYPE_SUPPLEMENTARY)
                svd.parse(vd, curr_extent)
                self.svds.append(svd)
            # Since we checked for the valid descriptors above, it is impossible
            # to see an invalid desc_type here, so no check necessary.

        # The language in Ecma-119, p.8, Section 6.7.1 says:
        #
        # The sequence shall contain one Primary Volume Descriptor (see 8.4)
        # recorded at least once.
        #
        # The important bit there is "at least one", which means that we have
        # to accept ISOs with more than one PVD.
        if not self.pvds:
            raise pycdlibexception.PyCdlibInvalidISO('Valid ISO9660 filesystems must have at least one PVD')

        self.pvd = self.pvds[0]

        # Make sure any other PVDs agree with the first one.
        for pvd in self.pvds[1:]:
            if pvd != self.pvd:
                raise pycdlibexception.PyCdlibInvalidISO('Multiple occurrences of PVD did not agree!')

            pvd.root_dir_record = self.pvd.root_dir_record

        if not self.vdsts:
            raise pycdlibexception.PyCdlibInvalidISO('Valid ISO9660 filesystems must have at least one Volume Descriptor Set Terminator')

    def _parse_path_table(self, ptr_size, extent):
        # type: (int, int) -> Tuple[List[path_table_record.PathTableRecord], Dict[int, path_table_record.PathTableRecord]]
        """
        An internal method to parse a path table on an ISO.  For each path
        table entry found, a Path Table Record object is created and added to
        the output list.

        Parameters:
         ptr_size - The size of the PTR table to read.
         extent - The extent at which this path table record starts.
        Returns:
         A tuple consisting of the list of path table record entries and a
         dictionary of the extent locations to the path table record entries.
        """
        if not self.is_hs:
            return super()._parse_path_table(ptr_size, extent)

        self._seek_to_extent(extent)
        old = self._cdfp.tell()
        data = self._cdfp.read(ptr_size)
        offset = 0
        out = []
        extent_to_ptr = {}
        while offset < ptr_size:
            ptr = HsPathTableRecord()

            len_di_byte = bytearray([data[offset+5]])[0]
            read_len = path_table_record.PathTableRecord.record_length(len_di_byte)

            ptr.parse(data[offset:offset + read_len])
            out.append(ptr)
            extent_to_ptr[ptr.extent_location] = ptr
            offset += read_len

        self._cdfp.seek(old)
        return out, extent_to_ptr

    def _walk_directories(self, vd, extent_to_ptr, extent_to_inode,
                          path_table_records):
        if not self.is_hs:
            return super()._walk_directories(vd, extent_to_ptr, extent_to_inode,
                                             path_table_records)
        cdfp = self._cdfp
        iso_file_length = self._get_iso_size()

        all_extent_to_dr = {}
        is_pvd = vd.is_pvd()
        root_dir_record = vd.root_directory_record()
        root_dir_record.set_ptr(path_table_records[0])
        interchange_level = 1
        parent_links = []
        child_links = []
        lastbyte = 0
        dirs = collections.deque([root_dir_record])
        while dirs:
            dir_record = dirs.popleft()

            self._seek_to_extent(dir_record.extent_location())
            length = dir_record.get_data_length()
            offset = 0
            last_record = None
            data = cdfp.read(length)
            while offset < length:
                if offset > (len(data) - 1):
                    # The data we read off of the ISO was shorter than what we
                    # expected.  The ISO is corrupt, throw an error.
                    raise pycdlibexception.PyCdlibInvalidISO('Invalid directory record')
                lenbyte = bytearray([data[offset]])[0]
                if lenbyte == 0:
                    # If we saw a zero length, this is probably the padding for
                    # the end of this extent.  Move the offset to the start of
                    # the next extent.
                    padsize = self.logical_block_size - (offset % self.logical_block_size)
                    if data[offset:offset + padsize] != b'\x00' * padsize:
                        # For now we are pedantic, and throw an exception if the
                        # padding bytes are not all zero.  We may have to loosen
                        # this check depending on what we see in the wild.
                        raise pycdlibexception.PyCdlibInvalidISO('Invalid padding on ISO')

                    offset = offset + padsize
                    continue

                new_record = HsDirectoryRecord()
                new_record.parse(vd, data[offset:offset + lenbyte], dir_record)
                offset += lenbyte

                # Cache some properties of this record for later use.
                is_symlink = new_record.is_symlink()
                dots = new_record.is_dot() or new_record.is_dotdot()
                rr_cl = new_record.rock_ridge is not None and new_record.rock_ridge.child_link_record_exists()
                is_dir = new_record.is_dir()
                data_length = new_record.get_data_length()
                new_extent_loc = new_record.extent_location()

                if is_pvd and not dots and not rr_cl and not is_symlink and new_extent_loc not in all_extent_to_dr:
                    all_extent_to_dr[new_extent_loc] = new_record

                # Some ISOs use random extent locations for zero-length files.
                # Thus, it is not valid for us to link zero-length files to
                # other files, as the linkage will be essentially random.
                # Ignore zero-length files (including symlinks) for linkage.
                # We don't do the lastbyte calculation on zero-length files for
                # the same reason.
                if not is_dir:
                    len_to_use = data_length
                    extent_to_use = new_extent_loc
                    # An important side-effect of this is that zero-length files
                    # or symlinks get an inode, but it is always set to length 0
                    # and location 0 and not actually written out.  This is so
                    # that we can 'link' everything through the Inode.
                    if len_to_use == 0 or is_symlink:
                        len_to_use = 0
                        extent_to_use = 0

                    # Directory Records that point to the El Torito Boot Catalog
                    # do not get Inodes since all of that is handled in-memory.
                    if self.eltorito_boot_catalog is not None and extent_to_use == self.eltorito_boot_catalog.extent_location():
                        self.eltorito_boot_catalog.add_dirrecord(new_record)
                    else:
                        # For real files, create an inode that points to the
                        # location on disk.
                        if extent_to_use in extent_to_inode:
                            ino = extent_to_inode[extent_to_use]
                        else:
                            ino = inode.Inode()
                            ino.parse(extent_to_use, len_to_use, cdfp,
                                      self.logical_block_size)
                            extent_to_inode[extent_to_use] = ino
                            self.inodes.append(ino)

                        ino.linked_records.append((new_record, vd == self.pvd))
                        new_record.inode = ino

                    new_end = extent_to_use * self.logical_block_size + len_to_use
                    if new_end > iso_file_length:
                        # The end of the file is beyond the size of the ISO.
                        # Since this can't be true, truncate the file size.
                        if new_record.inode is not None:
                            new_record.inode.data_length = iso_file_length - extent_to_use * self.logical_block_size
                            for rec, is_pvd in new_record.inode.linked_records:
                                rec.set_data_length(new_end)
                    else:
                        # The new end is still within the file size, but the PVD
                        # size is wrong.  Set the lastbyte appropriately, which
                        # will eventually be used to fix the PVD size.
                        lastbyte = max(lastbyte, new_end)

                if is_dir:
                    if new_record.rock_ridge is not None and new_record.rock_ridge.relocated_record():
                        self._rr_moved_record = new_record

                    if new_record.is_dotdot() and new_record.rock_ridge is not None and new_record.rock_ridge.parent_link_record_exists():
                        # Make sure to mark a dotdot record with a parent link
                        # record in the parent_links list for later linking.
                        parent_links.append(new_record)
                    if not dots and not rr_cl:
                        dirs.append(new_record)
                        new_record.set_ptr(extent_to_ptr[new_extent_loc])

                if new_record.parent is None:
                    raise pycdlibexception.PyCdlibInternalError('Trying to track child with no parent')
                try_long_entry = False
                try:
                    new_record.parent.track_child(new_record,
                                                  self.logical_block_size)
                except pycdlibexception.PyCdlibInvalidInput:
                    # dir_record.track_child() may throw a PyCdlibInvalidInput
                    # if it was given a duplicate child.  However, we allow
                    # duplicate children if and only if this record is a file
                    # and the last file has the same name; this represents a
                    # very large file.
                    if new_record.is_dir() or last_record is None or last_record.file_identifier() != new_record.file_identifier():
                        raise

                    try_long_entry = True

                if try_long_entry:
                    new_record.parent.track_child(new_record,
                                                  self.logical_block_size, True)

                if is_pvd:
                    if new_record.is_dir():
                        new_level = _interchange_level_from_directory(new_record.file_identifier())
                    else:
                        new_level = _interchange_level_from_filename(new_record.file_identifier())
                    interchange_level = max(interchange_level, new_level)

                last_record = new_record

        for pl in parent_links:
            if pl.rock_ridge is not None:
                pl.rock_ridge.parent_link = all_extent_to_dr[pl.rock_ridge.parent_link_extent()]

        for cl in child_links:
            if cl.rock_ridge is not None:
                cl.rock_ridge.cl_to_moved_dr = all_extent_to_dr[cl.rock_ridge.child_link_extent()]
                if cl.rock_ridge.cl_to_moved_dr.rock_ridge is not None:
                    cl.rock_ridge.cl_to_moved_dr.rock_ridge.moved_to_cl_dr = cl

        return interchange_level, lastbyte

# Volume descriptor parsers with HS filesystem support
class PrimaryOrSupplementaryVD(_PrimaryOrSupplementaryVD):
    FMT_HS = '<B5sBB32s32sQLL32sHHHHHHLLLLLLLLLL34s128s128s128s128s37s37s17s17s17s17sBB512s653s'
    def __init__(self, vd_type):
        super().__init__(vd_type)
        self.root_dir_record = HsDirectoryRecord()

    def parse(self, vd, ident, extent_loc):
        # type: (bytes, bytes, int) -> None
        """
        Parse a Volume Descriptor out of a string.

        Parameters:
         vd - The string containing the Volume Descriptor.
         ident - the ident of the descriptor
         extent_loc - The location on the ISO of this Volume Descriptor.
        Returns:
         Nothing.
        """
        if ident != b'CDROM':
            return super().parse(vd, extent_loc)

        ################ PVD VERSION ######################
        (descriptor_type, identifier, self.version, self.flags,
         self.system_identifier, self.volume_identifier, unused1,
         space_size_le, space_size_be, self.escape_sequences, set_size_le,
         set_size_be, seqnum_le, seqnum_be, logical_block_size_le,
         logical_block_size_be, path_table_size_le, path_table_size_be,
         self.path_table_location_le, opt_path_table_1_le, opt_path_table_2_le,
         opt_path_table_3_le, self.path_table_location_be, opt_path_table_1_be,
         opt_path_table_2_be, opt_path_table_3_msb,
         root_dir_record, self.volume_set_identifier, pub_ident_str,
         prepare_ident_str, app_ident_str, self.copyright_file_identifier,
         self.abstract_file_identifier,vol_create_date_str, vol_mod_date_str,
         vol_expire_date_str, vol_effective_date_str, self.file_structure_version,
         unused2, self.application_use, zero_unused) = struct.unpack_from(self.FMT_HS, vd, 0)

        # According to Ecma-119, 8.4.1, the primary volume descriptor type
        # should be 1.
        if descriptor_type != self._vd_type:
            raise pycdlibexception.PyCdlibInvalidISO('Invalid volume descriptor')
        # According to Ecma-119, 8.4.2, the identifier should be 'CD001'.
        if identifier != b'CDROM':
            raise pycdlibexception.PyCdlibInvalidISO('invalid CD isoIdentification')
        # According to Ecma-119, 8.4.3, the version should be 1 (or 2 for
        # ISO9660:1999)
        expected_versions = [1]
        if self._vd_type == headervd.VOLUME_DESCRIPTOR_TYPE_SUPPLEMENTARY:
            expected_versions.append(2)
        if self.version not in expected_versions:
            raise pycdlibexception.PyCdlibInvalidISO('Invalid volume descriptor version %d' % (self.version))
        # According to Ecma-119, 8.4.4, the first flags field should be 0 for a Primary.
        if self._vd_type == headervd.VOLUME_DESCRIPTOR_TYPE_PRIMARY and self.flags != 0:
            raise pycdlibexception.PyCdlibInvalidISO('PVD flags field is not zero')
        # According to Ecma-119, 8.4.5, the first unused field (after the
        # system identifier and volume identifier) should be 0.
        if unused1 != 0:
            raise pycdlibexception.PyCdlibInvalidISO('data in 2nd unused field not zero')
        # According to Ecma-119, 8.4.9, the escape sequences for a PVD should
        # be 32 zero-bytes.  However, we have seen ISOs in the wild (Fantastic
        # Night Dreams - Cotton Original (Japan).cue from the psx redump
        # collection) that don't have this set to 0, so allow anything here.

        # According to Ecma-119, 8.4.30, the file structure version should be 1.
        # However, we have seen ISOs in the wild that that don't have this
        # properly set to one.  In those cases, forcibly set it to one and let
        # it pass.
        if self._vd_type == headervd.VOLUME_DESCRIPTOR_TYPE_PRIMARY:
            if self.file_structure_version != 1:
                self.file_structure_version = 1
        elif self._vd_type == headervd.VOLUME_DESCRIPTOR_TYPE_SUPPLEMENTARY:
            if self.file_structure_version not in (1, 2):
                raise pycdlibexception.PyCdlibInvalidISO('File structure version expected to be 1')
        # According to Ecma-119, 8.4.31, the second unused field should be 0.
        if unused2 != 0:
            raise pycdlibexception.PyCdlibInvalidISO('data in 2nd unused field not zero')
        # According to Ecma-119, the last 653 bytes of the VD should be all 0.
        # However, we have seen ISOs in the wild that do not follow this, so
        # relax the check.

        # Check to make sure that the little-endian and big-endian versions
        # of the parsed data agree with each other.
        if space_size_le != utils.swab_32bit(space_size_be):
            raise pycdlibexception.PyCdlibInvalidISO('Little-endian and big-endian space size disagree')
        self.space_size = space_size_le

        if set_size_le != utils.swab_16bit(set_size_be):
            raise pycdlibexception.PyCdlibInvalidISO('Little-endian and big-endian set size disagree')
        self.set_size = set_size_le

        if seqnum_le != utils.swab_16bit(seqnum_be):
            raise pycdlibexception.PyCdlibInvalidISO('Little-endian and big-endian seqnum disagree')
        self.seqnum = seqnum_le

        if logical_block_size_le != utils.swab_16bit(logical_block_size_be):
            raise pycdlibexception.PyCdlibInvalidISO('Little-endian and big-endian logical block size disagree')
        self.log_block_size = logical_block_size_le

        if path_table_size_le != utils.swab_32bit(path_table_size_be):
            raise pycdlibexception.PyCdlibInvalidISO('Little-endian and big-endian path table size disagree')
        self.path_tbl_size = path_table_size_le
        self.path_table_num_extents = utils.ceiling_div(self.path_tbl_size, 4096) * 2

        self.path_table_location_be = utils.swab_32bit(self.path_table_location_be)

        self.encoding = 'ascii'
        if self.escape_sequences in (
        b'%/@'.ljust(32, b'\x00'), b'%/C'.ljust(32, b'\x00'), b'%/E'.ljust(32, b'\x00')):
            self.encoding = 'utf-16_be'

        self.publisher_identifier = headervd.FileOrTextIdentifier()
        self.publisher_identifier.parse(pub_ident_str)
        self.preparer_identifier = headervd.FileOrTextIdentifier()
        self.preparer_identifier.parse(prepare_ident_str)
        self.application_identifier = headervd.FileOrTextIdentifier()
        self.application_identifier.parse(app_ident_str)
        self.volume_creation_date = dates.VolumeDescriptorDate()
        self.volume_creation_date.parse(vol_create_date_str)
        self.volume_modification_date = dates.VolumeDescriptorDate()
        self.volume_modification_date.parse(vol_mod_date_str)
        self.volume_expiration_date = dates.VolumeDescriptorDate()
        self.volume_expiration_date.parse(vol_expire_date_str)
        self.volume_effective_date = dates.VolumeDescriptorDate()
        self.volume_effective_date.parse(vol_effective_date_str)
        self.root_dir_record.parse(self, root_dir_record, None)

        self.orig_extent_loc = extent_loc

        self._initialized = True


class VolumeDescriptorSetTerminator(_VolumeDescriptorSetTerminator):
    """
    A class that represents a Volume Descriptor Set Terminator.  The VDST
    signals the end of volume descriptors on the ISO.
    """
    __slots__ = ('_initialized', 'orig_extent_loc', 'new_extent_loc')

    FMT = '=B5sB2041s'

    def __init__(self):
        # type: () -> None
        self.new_extent_loc = -1
        self._initialized = False

    def parse(self, vd, extent_loc):
        # type: (bytes, int) -> None
        """
        Parse a Volume Descriptor Set Terminator out of a string.

        Parameters:
         vd - The string to parse.
         extent_loc - The extent this VDST is currently located at.
        Returns:
         Nothing.
        """
        if self._initialized:
            raise pycdlibexception.PyCdlibInternalError('Volume Descriptor Set Terminator already initialized')

        (descriptor_type, identifier, version,
         zero_unused) = struct.unpack_from(self.FMT, vd, 0)

        # According to Ecma-119, 8.3.1, the volume descriptor set terminator
        # type should be 255
        if descriptor_type != headervd.VOLUME_DESCRIPTOR_TYPE_SET_TERMINATOR:
            raise pycdlibexception.PyCdlibInvalidISO('Invalid VDST descriptor type')
        # According to Ecma-119, 8.3.2, the identifier should be 'CD001'
        # For legacy High Sierra fs, the identifier should be 'CDROM'
        if identifier not in [b'CDROM', b'CD001']:
            raise pycdlibexception.PyCdlibInvalidISO('Invalid VDST identifier')
        # According to Ecma-119, 8.3.3, the version should be 1
        # However, we've seen ISOs in the wild (mostly those created by
        # makeps3iso at https://github.com/bucanero/ps3iso-utils) that set the
        # VDST to 0, so accept that as well.
        if version not in (0, 1):
            raise pycdlibexception.PyCdlibInvalidISO('Invalid VDST version')
        # According to Ecma-119, 8.3.4, the rest of the terminator should be 0;
        # however, we have seen ISOs in the wild that put stuff into this field.
        # Just ignore it.

        self.orig_extent_loc = extent_loc

        self._initialized = True


class HsPathTableRecord(path_table_record.PathTableRecord):
    """A class that represents a single ISO9660 Path Table Record."""
    __slots__ = ('_initialized', 'len_di', 'xattr_length', 'extent_location',
                 'parent_directory_num', 'directory_identifier', 'dirrecord')

    FMT = '<IBBH'

    def parse(self, data):
        # type: (bytes) -> None
        """
        Parse an ISO9660 Path Table Record out of a string.

        Parameters:
         data - The string to parse.
        Returns:
         Nothing.
        """
        if self._initialized:
            raise pycdlibexception.PyCdlibInternalError('Path Table Record already initialized')

        (self.extent_location, self.xattr_length, self.len_di,
         self.parent_directory_num) = struct.unpack_from(self.FMT, data[:8], 0)

        if self.len_di % 2 != 0:
            self.directory_identifier = data[8:-1]
        else:
            self.directory_identifier = data[8:]
        self.dirrecord = None
        self._initialized = True


class HsDirectoryRecord(_DirectoryRecord):
    FMT = '<BBLLLL6sBBBBHHB'

    def parse(self, vd, record, parent):
        # type: (headervd.PrimaryOrSupplementaryVD, bytes, Optional[DirectoryRecord]) -> str
        """
        Parse a directory record out of a string.

        Parameters:
         vd - The Volume Descriptor this record is part of.
         record - The string to parse for this record.
         parent - The parent of this record.
        Returns:
         The Rock Ridge version as a string if this Directory Record has Rock
         Ridge, '' otherwise.
        """
        if self.initialized:
            raise pycdlibexception.PyCdlibInternalError('Directory Record already initialized')

        if len(record) > 255:
            # Since the length is supposed to be 8 bits, this should never
            # happen.
            raise pycdlibexception.PyCdlibInvalidISO('Directory record longer than 255 bytes!')

        # According to http://www.dubeyko.com/development/FileSystems/ISO9960/ISO9960.html,
        # the xattr_len is the number of bytes at the *beginning* of the file
        # extent.  Since this is only a byte, it is necessarily limited to 255
        # bytes.
        (self.dr_len, self.xattr_len, extent_location_le, extent_location_be,
         data_length_le, data_length_be_unused, dr_date, self.file_flags,
         reserved_unused, interleave_size, self.interleave_gap_size, seqnum_le,
         seqnum_be, self.len_fi) = struct.unpack_from(self.FMT, record[:33], 0)

        # In theory we should have a check here that checks to make sure that
        # the length of the record we were passed in matches the data record
        # length.  However, we have seen ISOs in the wild where this is
        # incorrect, so we elide the check here.

        if extent_location_le != utils.swab_32bit(extent_location_be):
            raise pycdlibexception.PyCdlibInvalidISO('Little-endian (%d) and big-endian (%d) extent location disagree' % (extent_location_le, utils.swab_32bit(extent_location_be)))
        self.orig_extent_loc = extent_location_le

        # Theoretically, we should check to make sure that the little endian
        # data length is the same as the big endian data length.  In practice,
        # though, we've seen ISOs where this is wrong.  Skip the check, and just
        # pick the little-endian as the 'actual' size, and hope for the best.

        self.data_length = data_length_le

        if seqnum_le != utils.swab_16bit(seqnum_be):
            raise pycdlibexception.PyCdlibInvalidISO('Little-endian and big-endian seqnum disagree')
        self.seqnum = seqnum_le

        self.date = HsDirectoryRecordDate()
        self.date.parse(dr_date)

        # OK, we've unpacked what we can from the beginning of the string.  Now
        # we have to use the len_fi to get the rest.

        self.parent = parent
        self.vd = vd

        if self.parent is None:
            self.is_root = True

            # A root directory entry should always be exactly 34 bytes.
            # However, we have seen ISOs in the wild that get this wrong, so we
            # elide a check for it.

            self.file_ident = bytes(bytearray([record[33]]))

            # A root directory entry should always have 0 as the identifier.
            # However, we have seen ISOs in the wild that don't have this set
            # properly to 0.  In that case, we override what we parsed out from
            # the original with the correct value (\x00), and hope for the best.
            if self.file_ident != b'\x00':
                self.file_ident = b'\x00'
            self.isdir = True
        else:
            record_offset = 33
            self.file_ident = record[record_offset:record_offset + self.len_fi]
            record_offset += self.len_fi
            if self.file_flags & (1 << self.FILE_FLAG_DIRECTORY_BIT):
                self.isdir = True

            if self.len_fi % 2 == 0:
                record_offset += 1

        if self.is_root:
            self._printable_name = '/'.encode(vd.encoding)
        elif self.file_ident == b'\x00':
            self._printable_name = '.'.encode(vd.encoding)
        elif self.file_ident == b'\x01':
            self._printable_name = '..'.encode(vd.encoding)
        else:
            self._printable_name = self.file_ident

        if self.parent is not None:
            xa_rec = XARecord()
            if xa_rec.parse(record[record_offset:], self.len_fi):
                self.xa_record = xa_rec
                record_offset += len(self.xa_record.record())

        if self.xattr_len != 0:
            if self.file_flags & (1 << self.FILE_FLAG_RECORD_BIT):
                raise pycdlibexception.PyCdlibInvalidISO('Record Bit not allowed with Extended Attributes')
            if self.file_flags & (1 << self.FILE_FLAG_PROTECTION_BIT):
                raise pycdlibexception.PyCdlibInvalidISO('Protection Bit not allowed with Extended Attributes')

        self.initialized = True

        return ''


class HsDirectoryRecordDate(dates.DirectoryRecordDate):
    FMT = '=BBBBBB'

    def parse(self, datestr):
        if self._initialized:
            raise pycdlibexception.PyCdlibInternalError('Directory Record Date already initialized')

        (self.years_since_1900, self.month, self.day_of_month, self.hour,
         self.minute, self.second) = struct.unpack_from(self.FMT, datestr, 0)

        self.gmtoffset = 0
        self._initialized = True
