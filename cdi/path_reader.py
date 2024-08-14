import io
import logging
from os.path import basename

from common.iso_path_reader.methods.base import IsoPathReader

LOGGER = logging.getLogger(__name__)


class CdiPathReader(IsoPathReader):
    volume_type = "cdi"

    def get_root_dir(self):
        return self.iso.path_tbl

    def iso_iterator(self, base_dir, recursive=False, include_dirs=False):
        for directory in base_dir:
            for file in directory.contents:
                if file.name == b"\x00" or file.name == b"\x01":
                    continue

                if file.attributes.directory and not include_dirs:
                    continue

                dir_name = b"/" + directory.name
                if directory.name == b"\x00" or directory.name == b"\x01":
                    dir_name = b""

                file.path = (dir_name + b"/" + file.name).decode()
                yield file
            if not recursive:
                break

    def get_file(self, path):
        file_basename = basename(path)
        if not isinstance(file_basename, bytes):
            file_basename = file_basename.encode()
        for file in self.iso_iterator(self.get_root_dir(), recursive=True):
            if file.name == file_basename:
                return file

    def open_file(self, file):
        f = io.BytesIO()
        lbn = file.first_lbn
        size_left = file.size
        while size_left > 0:
            try:
                block = self.iso.block(lbn)
            except IndexError:
                if lbn == file.first_lbn:
                    return f
                break
            f.write(block.data[0:min(block.data_size, size_left)])
            lbn += 1
            size_left -= block.data_size
        f.seek(0)
        return f

    def get_file_path(self, file):
        if hasattr(file, "path"):
            return file.path
        return file.name

    def get_file_date(self, file):
        return file.creation_date

    def get_file_hash(self, file, algo):
        lbn = file.first_lbn
        hash = algo()
        size_left = file.size
        while size_left > 0:
            try:
                block = self.iso.block(lbn)
            except IndexError:
                if lbn == file.first_lbn:
                    LOGGER.warning("File %s out of iso range", self.get_file_path(file))
                    return
                LOGGER.warning("File %s partially out of iso range. Read %d bytes out of %d bytes",
                               self.get_file_path(file), file.size - size_left, self.get_file_size(file))
                break
            file_data = block.data[0:min(block.data_size, size_left)]
            hash.update(file_data)
            lbn += 1
            size_left -= block.data_size
        return hash

    def get_file_sector(self, file):
        return file.first_lbn

    def is_directory(self, file):
        return file.flags & file.FLAG_DIRECTORY

    def get_pvd(self):
        return self.iso.disclabels[0]

    def get_pvd_info(self):
        disclabel = self.get_pvd()

        return {
            "system_identifier": disclabel.system_id.decode(),
            "volume_identifier": disclabel.volume_id.decode(),
            "volume_set_identifier": disclabel.album_id.decode(),
            "volume_creation_date": disclabel.creation_date,
            "volume_modification_date": disclabel.mod_date,
            "volume_expiration_date": disclabel.exp_date,
            "volume_effective_date": disclabel.effective_date,
        }
