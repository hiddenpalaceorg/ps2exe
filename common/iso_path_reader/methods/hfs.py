import io

from machfs import Folder

from common.iso_path_reader.methods.base import IsoPathReader
from common.iso_path_reader.methods.chunked_hash_trait import ChunkedHashTrait
from dates import datetime_from_hfs_date


class HfsPathReader(ChunkedHashTrait, IsoPathReader):
    def get_root_dir(self):
        return self.iso

    def iso_iterator(self, base_dir, recursive=False, include_dirs=False, base_path=tuple()):
        for name, child in base_dir.items():
            path = base_path + (name,)
            child.path = "/".join(path)
            if isinstance(child, Folder):
                if recursive:
                    if include_dirs:
                        yield child
                    yield from self.iso_iterator(child, recursive, include_dirs, path)
                continue

            yield child

    def get_file_path(self, file):
        return file.path

    def get_file_date(self, file):
        return datetime_from_hfs_date(file.crdate)

    def get_file(self, path):
        if path[0] == "/":
            path = path[1:]

        path = path.split("/")
        try:
            return self.iso[tuple(path)]
        except KeyError:
            raise FileNotFoundError

    def open_file(self, file):
        return io.BytesIO(file.data)

    def get_file_size(self, file):
        return file.size

    def get_file_sector(self, file):
        return file.start_lba

    def is_directory(self, file):
        return isinstance(file, Folder)

    def get_pvd(self):
        return None

    def get_pvd_info(self):
        return {
            "volume_identifier": self.iso.name,
            "volume_creation_date": datetime_from_hfs_date(self.iso.crdate),
            "volume_modification_date": datetime_from_hfs_date(self.iso.mddate)
        }
