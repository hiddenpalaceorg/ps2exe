import logging
from pathlib import Path

from common.iso_path_reader.methods.base import IsoPathReader
from common.iso_path_reader.methods.chunked_hash_trait import ChunkedHashTrait

LOGGER = logging.getLogger(__name__)


class DirectoryPathReader(ChunkedHashTrait, IsoPathReader):
    volume_type = "directory"

    def __init__(self, iso):
        super().__init__(Path(iso).resolve(), None, None)

    def _checked(self, path):
        candidate = Path(path)
        if not candidate.is_absolute():
            # Callers may pass either a path relative to the disc root or the
            # original cwd-relative input (e.g. disc/track.bin).
            cwd_path = candidate.resolve()
            try:
                cwd_path.relative_to(self.iso)
                candidate = cwd_path
            except ValueError:
                candidate = self.iso / candidate
        resolved = candidate.resolve()
        try:
            resolved.relative_to(self.iso)
        except ValueError:
            raise PermissionError("path is outside the selected directory") from None
        return resolved

    def get_root_dir(self):
        return self.iso

    def iso_iterator(self, base_dir, recursive=False, include_dirs=False):
        base_dir = self._checked(base_dir)
        for file in base_dir.rglob("*") if recursive else base_dir.glob("*"):
            try:
                self._checked(file)
            except PermissionError:
                continue
            if not include_dirs and file.is_dir():
                continue
            yield file

    def get_file_path(self, file):
        self._checked(file)
        return str(file)

    def get_file_date(self, file):
        self._checked(file)
        return file

    def get_file_size(self, file):
        return self._checked(file).stat().st_size

    def is_directory(self, file):
        return self._checked(file).is_dir()

    def get_file(self, path):
        return self._checked(path)

    def open_file(self, file):
        return self._checked(file).open("rb")

    def get_parent_dir(self, file):
        return self._checked(self._checked(file).parent)

    def get_pvd_info(self):
        return {}

    def close(self):
        return
