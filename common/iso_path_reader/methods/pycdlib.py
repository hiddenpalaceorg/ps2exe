import logging

import pycdlib.pycdlibio
from pycdlib.pycdlib import _yield_children
from pycdlib.pycdlibexception import PyCdlibInvalidInput

from common.iso_path_reader.methods.base import IsoPathReader
from common.iso_path_reader.methods.chunked_hash_trait import ChunkedHashTrait
from dates import datetime_from_iso_date

LOGGER = logging.getLogger(__name__)


class PyCdLibPathReader(ChunkedHashTrait, IsoPathReader):
    def __init__(self, iso, fp, udf=False):
        super().__init__(iso, fp)
        self.udf = udf

    def get_root_dir(self):
        if self.udf:
            return self.iso.get_record(udf_path="/")
        else:
            return self.iso.get_record(iso_path="/")

    def iso_iterator(self, base_dir, recursive=False, include_dirs=False):
        for file in _yield_children(base_dir, rr=False) if not self.udf else base_dir.fi_descs:
            if self.udf:
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
            return self.iso.full_path_from_dirrecord(file).replace(";1", "")
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
        return datetime_from_iso_date(file.date if not self.udf else file.mod_time)

    def get_file_size(self, file):
        return file.get_data_length()

    def get_file_sector(self, file):
        return file.orig_extent_loc

    def is_directory(self, file):
        return file.is_dir()

    def get_file(self, path):
        if path[0] != "/":
            path = "/" + path
        try:
            if self.udf:
                return self.iso.get_record(udf_path=path)
            else:
                return self.iso.get_record(iso_path=path)
        except PyCdlibInvalidInput as e:
            try:
                if self.udf:
                    return self.iso.get_record(udf_path=path + ";1")
                else:
                    return self.iso.get_record(iso_path=path + ";1")
            except PyCdlibInvalidInput:
                if path.upper() != path:
                    return self.get_file(path.upper())
                if b'\xef\xbf\xbd' in path.encode():
                    for file in self.iso_iterator(self.get_root_dir(), recursive=True):
                        if path == self.get_file_path(file):
                            return file
                raise FileNotFoundError(e)

    def open_file(self, file):
        # Hack: If multiple files reference the same LBA but with different
        # sizes, update the inode's data size to be correct for this file
        if hasattr(file, "data_length"):
            if len(file.inode.linked_records) > 1 and file.inode.data_length != file.data_length:
                LOGGER.warning("File %s marked at LBA %d, which was already marked for file %s",
                               self.get_file_path(file), file.orig_extent_loc, self.get_file_path(file.inode.linked_records[0][0]))
                for dr, _ in file.inode.linked_records:
                    if file == dr:
                        file.inode.data_length = dr.data_length
            # Hack #2. If the inode reports a negative or truncated value, force it to be the original size
            if hasattr(file, "data_length") and file.inode.data_length < file.data_length:
                file.inode.data_length = file.data_length

        return pycdlib.pycdlibio.PyCdlibIO(file.inode, self.iso.logical_block_size)

    def get_pvd(self):
        return self.iso.pvd

    def get_pvd_info(self):
        if not self.udf:
            return super().get_pvd_info()

        pvd = self.iso.udf_main_descs.pvds[0]

        info = {}

        vol_ident = pvd.vol_ident[1:pvd.vol_ident[-1]]
        vol_set_ident = pvd.vol_set_ident[1:pvd.vol_set_ident[-1]]

        info["volume_identifier"] = vol_ident.decode(errors='replace')
        info["volume_set_identifier"] = vol_set_ident.decode(errors='replace')
        info["volume_creation_date"] = datetime_from_iso_date(pvd.recording_date)

        return info
