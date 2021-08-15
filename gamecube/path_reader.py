import io
import logging

from common.iso_path_reader.methods.base import IsoPathReader

LOGGER = logging.getLogger(__name__)

class GamecubePathReader(IsoPathReader):
    def get_root_dir(self):
        return self.iso.rootnode

    def iso_iterator(self, base_dir, recursive=False):
        for entry in base_dir.files:
            yield entry

        if not recursive:
            return
        for dir in base_dir.dirs:
            yield from self.iso_iterator(dir, recursive)

    def get_file(self, path):
        for file in self.iso_iterator(self.get_root_dir(), recursive=True):
            if file.path == path:
                return file
        raise FileNotFoundError

    def get_file_path(self, file):
        if hasattr(file, "path"):
            return file.path
        return file.name

    def get_file_date(self, file):
        return None

    def open_file(self, file):
        bio = io.BytesIO()
        size_left = file.size
        self.fp.seek(file.offset)
        while size_left > 0:
            chunk_size = min(65535, size_left)
            chunk = self.fp.read(chunk_size)
            bio.write(chunk)
            size_left -= chunk_size
        return bio

    def get_file_hash(self, file, algo):
        hash = algo()
        size_left = file.size
        try:
            self.fp.seek(file._fileoffset)
        except ValueError:
            LOGGER.warning("File %s out of iso range", self.get_file_path(file))
            return

        while size_left > 0:
            chunk_size = min(65535, size_left)
            chunk = self.fp.read(chunk_size)
            hash.update(chunk)
            size_left -= chunk_size
        return hash

    def get_pvd(self):
        return {}

    def get_pvd_info(self):
        return {}