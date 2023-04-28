import io
import logging

from common.iso_path_reader.methods.base import IsoPathReader

LOGGER = logging.getLogger(__name__)

class XboxPathReader(IsoPathReader):
    def get_root_dir(self):
        return self.iso.root

    def iso_iterator(self, base_dir, recursive=False, include_dirs=False):
        for entry in base_dir.entries:
            yield entry

        if not recursive:
            return
        for dir in base_dir.directories:
            if include_dirs:
                yield dir
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
        bio = io.BytesIO()
        size_left = file.size
        self.fp.seek(file.offset)
        while size_left > 0:
            chunk_size = min(65536, size_left)
            chunk = self.fp.read(chunk_size)
            bio.write(chunk)
            size_left -= chunk_size
        return bio

    def get_file_hash(self, file, algo):
        hash = algo()
        size_left = file.size
        try:
            self.fp.seek(file.offset)
        except ValueError:
            LOGGER.warning("File %s out of iso range", self.get_file_path(file))
            return

        while size_left > 0:
            chunk_size = min(65536, size_left)
            chunk = self.fp.read(chunk_size)
            hash.update(chunk)
            size_left -= chunk_size
        return hash

    def get_file_sector(self, file):
        return file.start_sector

    def is_directory(self, file):
        return file.__class__.__name__ == 'Directory'

    def get_pvd(self):
        return {}

    def get_pvd_info(self):
        return {}

class XboxStfsPathReader(XboxPathReader):
    def get_root_dir(self):
        return self.iso.allfiles

    def iso_iterator(self, base_dir, recursive=False):
        # always recursive
        for path, file in self.iso.allfiles.items():
            yield file

    def get_file(self, path):
        try:
            return self.iso.allfiles[path.encode()]
        except KeyError:
            raise FileNotFoundError

    def get_file_date(self, file):
        return None

    def get_file_path(self, file):
        return file.path.decode(errors="replace")

    def get_file_hash(self, file, algo):
        hash = algo()
        f = self.open_file(file)
        while chunk := f.read(65536):
            hash.update(chunk)
        return hash

    def open_file(self, file):
        return self.iso.read_file(file)

    def get_file_date(self, file):
        return None

    def get_pvd_info(self):
        return {}