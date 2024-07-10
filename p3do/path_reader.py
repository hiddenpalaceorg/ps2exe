from os.path import basename

from pycdlib import pycdlib

from common.iso_path_reader.methods.base import IsoPathReader
from common.iso_path_reader.methods.chunked_hash_trait import ChunkedHashTrait


class P3doPathReader(ChunkedHashTrait, IsoPathReader):
    def get_root_dir(self):
        return self.iso.superblock.root.root_copies[0]

    def iso_iterator(self, base_dir, recursive=False, include_dirs=False):
        for entry in base_dir.entries:
            if self.is_directory(entry) and not include_dirs:
                continue
            yield entry

        if not recursive:
            return
        for dir in base_dir.directories:
            yield from self.iso_iterator(dir, recursive)

    def get_file(self, path):
        for file in self.iso_iterator(self.get_root_dir(), recursive=True):
            if file.path == path:
                return file
        raise FileNotFoundError

    def get_file_path(self, file):
        if hasattr(file, "path"):
            return file.path
        return file.file_name

    def get_file_date(self, file):
        return None

    def open_file(self, file):
        inode = pycdlib.inode.Inode()
        inode.new(file.byte_length, self.fp, False, file.copy_offset * file.block_size)
        return pycdlib.pycdlibio.PyCdlibIO(inode, file.block_size)

    def get_file_sector(self, file):
        return file.copy_offset

    def is_directory(self, file):
        return file.flags & file.FLAG_DIRECTORY == file.FLAG_DIRECTORY

    def get_pvd(self):
        return self.iso.superblock.volume

    def get_file_size(self, file):
        return file.byte_length

    def get_pvd_info(self):
        pvd = self.get_pvd()

        return {
            "system_identifier": pvd.system_identifier,
            "volume_identifier": pvd.volume_identifier
        }
