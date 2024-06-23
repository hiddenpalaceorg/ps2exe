import logging

LOGGER = logging.getLogger(__name__)


class ChunkedHashTrait:
    def open_file(self, file):
        raise NotImplementedError

    def get_file_size(self, file):
        raise NotImplementedError

    def get_file_path(self, file):
        raise NotImplementedError

    def get_file_hash(self, file, algo):
        hash = algo()
        bytes_read = 0
        with self.open_file(file) as f:
            try:
                for chunk in iter(lambda: f.read(65536), b""):
                    bytes_read += len(chunk)
                    hash.update(chunk)
            except ValueError:
                pass

        if bytes_read:
            if bytes_read != self.get_file_size(file):
                LOGGER.warning("File %s partially out of iso range. Read %d bytes out of %d bytes",
                               self.get_file_path(file), bytes_read, self.get_file_size(file))
            return hash
        elif self.get_file_size(file):
            LOGGER.warning("File %s out of iso range", self.get_file_path(file))
            return

        return hash


