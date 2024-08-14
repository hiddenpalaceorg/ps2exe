import datetime
import io

from common.iso_path_reader.methods.base import IsoPathReader
from common.iso_path_reader.methods.chunked_hash_trait import ChunkedHashTrait
from exceptions import SkippableError


class CompressedPathReader(ChunkedHashTrait, IsoPathReader):
    volume_type = "archive"

    def __init__(self, iso, fp, *args, **kwargs):
        super().__init__(iso, fp, *args, **kwargs)
        iso.__enter__()

    def get_root_dir(self):
        return self.iso

    def iso_iterator(self, base_dir, recursive=False, include_dirs=False):
        try:
            # always recursive
            for file in self.iso:
                if self.is_directory(file) and not include_dirs:
                    continue
                yield file
        except Exception as e:
            skippable_errors = [
                "Passphrase required for this entry",
                "password required for extraction",
                "Unsupported ZIP compression method",
                "That compression method is not supported"
            ]
            if any(error for error in skippable_errors if error in str(e)):
                self.iso.__exit__(e)
                raise SkippableError(str(e))
            raise

    def get_file(self, path):
        if path in [".", "/", ""]:
            return self.get_root_dir()
        paths_to_try = [path, path.replace("\\", "/"), path.replace("/", "\\"), path + "/", path + "\\"]
        for file in self.iso_iterator(self.get_root_dir(), recursive=True, include_dirs=True):
            if file.path in paths_to_try:
                return file
        raise FileNotFoundError

    def get_file_date(self, file):
        return None

    def get_file_path(self, file):
        if self.is_directory(file):
            return file.path.rstrip("/").rstrip("\\")
        return file.path

    def get_file_size(self, file):
        return file.file_size

    def open_file(self, file):
        try:
            path = self.get_file_path(file)
            return self.iso.entries[path].open()
        except Exception as e:
            if (str(e).startswith("Passphrase required for this entry") or
                    str(e).endswith("password required for extraction")):
                self.iso.__exit__(e)
                raise SkippableError(str(e))
            raise

    # noinspection PyRedeclaration
    def get_file_date(self, file):
        try:
            if getattr(file, "date_time", None):
                return datetime.datetime(*file.date_time, tzinfo=datetime.timezone.utc)
            if isinstance(getattr(file, "mtime", None), datetime.datetime):
                return file.mtime
            elif getattr(file, "mtime", None) and file.mtime > 0:
                try:
                    return datetime.datetime.fromtimestamp(file.mtime, tz=datetime.timezone.utc)
                except OSError:
                    return None
        except ValueError:
            return None

    def get_pvd_info(self):
        return {}

    def get_pvd(self):
        return {}

    def is_directory(self, file):
        return file.is_dir

    def close(self):
        self.iso.__exit__(None, None, None)
