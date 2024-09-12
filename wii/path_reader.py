import io
import logging

from gamecube.path_reader import GamecubePathReader

LOGGER = logging.getLogger(__name__)

class WiiPathReader(GamecubePathReader):
    @property
    def volume_type(self):
        if not self.iso:
            return "wii"
        return f"wii partition {self.iso.partition.disc_infos.volume_group}:{self.iso.partition.disc_infos.index}"

    def open_file(self, file):
        bio = io.BytesIO()
        size_left = file.size
        self.iso.partition.seek(file._fileoffset)
        while size_left > 0:
            chunk_size = min(65536, size_left)
            chunk = self.iso.partition.read(chunk_size)
            bio.write(chunk)
            size_left -= chunk_size
        return bio

    def get_file_hash(self, file, algo):
        hash = algo()
        size_left = file.size
        try:
            self.iso.partition.seek(file._fileoffset)
        except ValueError:
            LOGGER.warning("File %s out of iso range", self.get_file_path(file))
            return None, file.size

        while size_left > 0:
            chunk_size = min(65536, size_left)
            try:
                chunk = self.iso.partition.read(chunk_size)
            except ValueError:
                LOGGER.warning("File %s partially out of iso range. Read %d bytes out of %d bytes",
                               self.get_file_path(file), file.size - size_left, self.get_file_size(file))
                break
            hash.update(chunk)
            size_left -= chunk_size
        return hash, size_left
