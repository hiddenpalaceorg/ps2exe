import logging
import os.path

from common.iso_path_reader.methods.base import IsoPathReader
from common.iso_path_reader.methods.chunked_hash_trait import ChunkedHashTrait

LOGGER = logging.getLogger(__name__)


class DirectoryPathReader(ChunkedHashTrait, IsoPathReader):
    volume_type = "directory"

    def __init__(self, iso):
        super().__init__(iso, None, None)

    def get_root_dir(self):
        return self.iso

    def iso_iterator(self, base_dir, recursive=False, include_dirs=False):
        for file in base_dir.rglob("*") if recursive else base_dir.glob("*"):
            if not include_dirs and file.is_dir():
                continue
            yield file

    def get_file_path(self, file):
        return str(file)

    def get_file_date(self, file):
        return file

    def get_file_size(self, file):
        return file.stat().st_size

    def is_directory(self, file):
        return file.is_dir()

    def get_file(self, path):
        return self.get_root_dir() / path.replace(str(self.get_root_dir()) + os.path.sep, "")

    def open_file(self, file):
        return file.open("rb")

    def get_parent_dir(self, file):
        return file.parent

    def get_pvd_info(self):
        return {}

    def close(self):
        return
