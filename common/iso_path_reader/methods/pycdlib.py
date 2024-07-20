import logging

import pycdlib.inode
import pycdlib.pycdlibio
from pycdlib.pycdlib import _yield_children
from pycdlib.pycdlibexception import PyCdlibInvalidInput

import utils.files
from common.iso_path_reader.methods.base import IsoPathReader
from common.iso_path_reader.methods.chunked_hash_trait import ChunkedHashTrait
from dates import datetime_from_iso_date
from utils.files import ConcatenatedFile

LOGGER = logging.getLogger(__name__)


class PyCdLibPathReader(ChunkedHashTrait, IsoPathReader):
    def __init__(self, iso, fp, *args, volume_type, **kwargs):
        super().__init__(iso, fp, *args, **kwargs)
        self.volume_type = volume_type

    @property
    def pycdlib_volume_type(self):
        if self.volume_type == "iso9660":
            return "iso"
        elif self.volume_type == "rock_ridge":
            return "rr"
        elif self.volume_type == "joliet":
            return "joliet"
        elif self. volume_type == "udf":
            return "udf"
        return self.volume_type

    def get_root_dir(self):
        return self.iso.get_record(**{f"{self.pycdlib_volume_type}_path":"/"})

    def iso_iterator(self, base_dir, recursive=False, include_dirs=False):
        for file in _yield_children(base_dir, rr=self.volume_type=="rock_ridge") if not self.volume_type == "udf" else base_dir.fi_descs:
            if self.volume_type == "udf":
                file = file.file_entry

            if not file or file.is_dot() or file.is_dotdot():
                continue

            if file.is_dir():
                if recursive:
                    if include_dirs:
                        yield file
                    yield from self.iso_iterator(file, recursive)
                continue

            yield file

    def get_file_path(self, file):
        try:
            return self.iso.full_path_from_dirrecord(file, rockridge=self.volume_type == "rock_ridge").replace(";1", "")
        except UnicodeDecodeError:
            path = []
            while not file.is_root:
                path.append(file.file_ident)
                file = file.parent
            path = b"/" + b"/".join(reversed(path))
            return path.decode(errors="replace").replace(";1", "")

    def get_file_date(self, file):
        return datetime_from_iso_date(file.date if not self.volume_type == "udf" else file.mod_time)

    def get_file_size(self, file):
        try:
            return file.data_length
        except AttributeError:
            try:
                return file.inode.data_length
            except AttributeError:
                return file.get_data_length()

    def get_file_sector(self, file):
        return file.orig_extent_loc

    def is_directory(self, file):
        return file.is_dir()

    def get_file(self, path):
        if path[0] != "/":
            path = "/" + path
        try:
            return self.iso.get_record(**{f"{self.pycdlib_volume_type}_path": path})
        except PyCdlibInvalidInput as e:
            try:
                return self.iso.get_record(**{f"{self.pycdlib_volume_type}_path":path + ";1"})
            except PyCdlibInvalidInput:
                try:
                    for file in self.iso_iterator(self.get_root_dir(), recursive=True):
                        if path.lower() == self.get_file_path(file).lower():
                            return file
                except:
                    pass
                raise FileNotFoundError(e)

    def open_file(self, file):
        # Hack: If multiple files reference the same LBA but with different
        # sizes, update the inode's data size to be correct for this file
        if hasattr(file, "data_length"):
            if not file.inode:
                inode = pycdlib.inode.Inode()
                inode.parse(file.extent_location(), file.data_length, self.fp,
                          self.iso.logical_block_size)
                f = pycdlib.pycdlibio.PyCdlibIO(inode, self.iso.logical_block_size)
                f.name = self.get_file_path(file)
                return f

            if len(file.inode.linked_records) > 1 and file.inode.data_length != file.data_length:
                LOGGER.warning("File %s marked at LBA %d, which was already marked for file %s",
                               self.get_file_path(file), file.orig_extent_loc, self.get_file_path(file.inode.linked_records[0][0]))
                for dr, _ in file.inode.linked_records:
                    if file == dr:
                        file.inode.data_length = dr.data_length
            # Hack #2. If the inode reports a negative or truncated value, force it to be the original size
            if hasattr(file, "data_length") and file.inode.data_length < file.data_length:
                file.inode.data_length = file.data_length

        if self.volume_type == "udf" and len(file.alloc_descs) > 1:
            part_start = self.iso.udf_main_descs.partitions[0].part_start_location
            readers = []
            offsets = [0]
            for alloc_desc in file.alloc_descs:
                start_pos = (part_start + alloc_desc.log_block_num) * self.iso.logical_block_size
                readers.append(
                    utils.files.OffsetFile(
                        self.fp,
                        start_pos,
                        start_pos + alloc_desc.extent_length
                    )
                )
                offsets.append(alloc_desc.extent_length + offsets[-1])
            f = ConcatenatedFile(readers, offsets[0:-1])
        else:
            f = pycdlib.pycdlibio.PyCdlibIO(file.inode, self.iso.logical_block_size)
        f.name = self.get_file_path(file)
        return f

    def get_pvd(self):
        if self.volume_type == "joliet":
            return self.iso.joliet_vd
        return self.iso.pvd

    def get_pvd_info(self):
        if not self.volume_type == "udf":
            return super().get_pvd_info()

        pvd = self.iso.udf_main_descs.pvds[0]

        info = {}

        vol_ident = pvd.vol_ident[1:pvd.vol_ident[-1]]
        vol_set_ident = pvd.vol_set_ident[1:pvd.vol_set_ident[-1]]

        info["volume_identifier"] = vol_ident.decode(errors='replace')
        info["volume_set_identifier"] = vol_set_ident.decode(errors='replace')
        info["volume_creation_date"] = datetime_from_iso_date(pvd.recording_date)

        return info
