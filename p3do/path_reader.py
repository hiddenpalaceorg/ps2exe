from os.path import basename

from common.iso_path_reader.methods.base import IsoPathReader


class P3doPathReader(IsoPathReader):
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

    def get_file_hash(self, file, algo):
        hash = algo()
        size_left = file.byte_length
        self.fp.seek(file.copy_offset * file.block_size)
        while size_left > 0:
            chunk_size = min(65536, size_left)
            chunk = self.fp.read(chunk_size)
            hash.update(chunk)
            size_left -= chunk_size
        return hash

    def get_file_sector(self, file):
        return file.copy_offset

    def is_directory(self, file):
        return file.flags == file.FLAG_DIRECTORY

    def get_pvd(self):
        return self.iso.superblock.volume

    def get_pvd_info(self):
        pvd = self.get_pvd()

        return {
            "system_identifier": pvd.system_identifier,
            "volume_identifier": pvd.volume_identifier
        }