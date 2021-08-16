import io
import logging

from gamecube.path_reader import GamecubePathReader

LOGGER = logging.getLogger(__name__)

class WiiPathReader(GamecubePathReader):
    def open_file(self, file):
        bio = io.BytesIO()
        size_left = file.size
        self.iso.partition.seek(file.offset)
        while size_left > 0:
            chunk_size = min(65535, size_left)
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
            return

        while size_left > 0:
            chunk_size = min(65535, size_left)
            chunk = self.iso.partition.read(chunk_size)
            hash.update(chunk)
            size_left -= chunk_size
        return hash