import pycdlib.pycdlibio
from pycdlib.pycdlib import _yield_children
from pycdlib.pycdlibexception import PyCdlibInvalidInput

from common.iso_path_reader.methods.base import IsoPathReader
from dates import datetime_from_iso_date


class PyCdLibPathReader(IsoPathReader):
    def get_root_dir(self):
        return self.iso.get_record(iso_path="/")

    def iso_iterator(self, base_dir, recursive=False):
        for file in _yield_children(base_dir):
            if file.is_dot() or file.is_dotdot():
                continue

            if file.is_dir():
                if recursive:
                    yield from self.iso_iterator(file, recursive)
                continue

            yield file

    def get_file_path(self, file):
        try:
            return self.iso.full_path_from_dirrecord(file)
        except UnicodeDecodeError:
            return file.file_ident.decode(errors="replace")

    def get_file_date(self, file):
        return datetime_from_iso_date(file.date)

    def get_file(self, path):
        if path[0] != "/":
            path = "/" + path
        try:
            return self.iso.get_record(iso_path=path)
        except PyCdlibInvalidInput as e:
            try:
                return self.iso.get_record(iso_path=path + ";1")
            except PyCdlibInvalidInput:
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