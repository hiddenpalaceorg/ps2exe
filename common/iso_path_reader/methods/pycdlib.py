import logging
import pathlib

import pycdlib.inode
import pycdlib.pycdlibio
from pycdlib.pycdlib import _yield_children
from pycdlib.pycdlibexception import PyCdlibInvalidInput

from common.iso_path_reader.methods.base import IsoPathReader
from common.iso_path_reader.methods.chunked_hash_trait import ChunkedHashTrait
from dates import datetime_from_iso_date
from utils.files import ConcatenatedFile
from utils.mmap import FakeMemoryMap

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
                    yield from self.iso_iterator(file, recursive, include_dirs)
                continue

            yield file

    def get_file_path(self, file):
        try:
            return self.iso.full_path_from_dirrecord(
                file, rockridge=self.volume_type == "rock_ridge"
            ).replace(";1", "").rstrip(".")
        except UnicodeDecodeError:
            path = []
            while file.parent:
                ident = file.file_identifier()
                if hasattr(file, "file_ident") and hasattr(file.file_ident, "encoding"):
                    path.append(f"{ident.decode(file.file_ident.encoding, errors='replace')}")
                else:
                    path.append(ident.decode(errors="replace").replace(";1", ""))
                file = file.parent
            return "/" + "/".join(reversed(path))

    def get_file_date(self, file):
        return datetime_from_iso_date(file.date if not self.volume_type == "udf" else file.mod_time)

    def get_file_size(self, file):
        size = 0
        try:
            size += file.data_length
        except AttributeError:
            try:
                size += file.inode.data_length
            except AttributeError:
                size += file.get_data_length()
        if getattr(file, "data_continuation", None):
            while file.data_continuation:
                file = file.data_continuation
                size += file.get_data_length()
        return size

    def get_file_sector(self, file):
        return file.orig_extent_loc

    def is_directory(self, file):
        return file.is_dir()

    def get_file(self, path):
        if path[0] == "\\":
            path = pathlib.Path(path).as_posix()
        if path[0] != "/":
            path = "/" + path
        try:
            f = self.iso.get_record(**{f"{self.pycdlib_volume_type}_path": path})
        except (PyCdlibInvalidInput, IndexError) as e:
            try:
                f = self.iso.get_record(**{f"{self.pycdlib_volume_type}_path":path + ";1"})
            except (PyCdlibInvalidInput, IndexError):
                try:
                    for file in self.iso_iterator(self.get_root_dir(), recursive=True):
                        if path.lower() == self.get_file_path(file).lower():
                            return file
                except Exception:
                    pass
                raise FileNotFoundError(e)
        if not f:
            raise FileNotFoundError
        return f

    def open_file(self, file, file_io_cls=pycdlib.pycdlibio.PyCdlibIO):
        # Hack: If multiple files reference the same LBA but with different
        # sizes, update the inode's data size to be correct for this file
        if hasattr(file, "data_length"):
            if not file.inode:
                inode = pycdlib.inode.Inode()
                inode.parse(file.extent_location(), file.data_length, self.fp,
                          self.iso.logical_block_size)
                f = file_io_cls(inode, self.iso.logical_block_size)
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
                inode = pycdlib.inode.Inode()
                inode.parse(part_start + alloc_desc.log_block_num, alloc_desc.extent_length, self.fp,
                            self.iso.logical_block_size)
                f = file_io_cls(inode, self.iso.logical_block_size)
                f.__enter__()
                readers.append(FakeMemoryMap(f))
                offsets.append(alloc_desc.extent_length + offsets[-1])
            f = ConcatenatedFile(readers, offsets[0:-1])
        elif getattr(file, "data_continuation", None):
            f = file_io_cls(file.inode, self.iso.logical_block_size)
            f.__enter__()
            readers = [FakeMemoryMap(f)]
            offsets = [0]
            while file.data_continuation:
                offsets.append(file.get_data_length())
                file = file.data_continuation
                f = file_io_cls(file.inode, self.iso.logical_block_size)
                f.__enter__()
                readers.append(FakeMemoryMap(f))
            f = ConcatenatedFile(readers, offsets)
        else:
            f = file_io_cls(file.inode, self.iso.logical_block_size)
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
