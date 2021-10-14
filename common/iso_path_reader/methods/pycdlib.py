import pycdlib.pycdlibio
from pycdlib.pycdlib import _yield_children
from pycdlib.pycdlibexception import PyCdlibInvalidInput

from common.iso_path_reader.methods.base import IsoPathReader
from dates import datetime_from_iso_date


class PyCdLibPathReader(IsoPathReader):
    def __init__(self, iso, fp, udf=False):
        super().__init__(iso, fp)
        self.udf = udf

    def get_root_dir(self):
        if self.udf:
            return self.iso.get_record(udf_path="/")
        else:
            return self.iso.get_record(iso_path="/")

    def iso_iterator(self, base_dir, recursive=False):
        for file in _yield_children(base_dir) if not self.udf else base_dir.fi_descs:
            if self.udf:
                file = file.file_entry

            if not file or file.is_dot() or file.is_dotdot():
                continue

            if file.is_dir():
                if recursive:
                    yield from self.iso_iterator(file, recursive)
                continue

            yield file

    def get_file_path(self, file):
        try:
            return self.iso.full_path_from_dirrecord(file).replace(";1", "")
        except UnicodeDecodeError:
            return file.file_ident.decode(errors="replace").replace(";1", "")

    def get_file_date(self, file):
        return datetime_from_iso_date(file.date if not self.udf else file.mod_time)

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
                raise FileNotFoundError(e)


    def open_file(self, file):
        return pycdlib.pycdlibio.PyCdlibIO(file.inode, self.iso.logical_block_size)

    def get_file_hash(self, file, algo):
        hash = algo()
        with self.open_file(file) as f:
            for chunk in iter(lambda: f.read(65535), b""):
                hash.update(chunk)

        return hash

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