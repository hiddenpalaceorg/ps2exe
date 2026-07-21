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
            while True:
                try:
                    chunk = f.read(65536)
                except ValueError:
                    # early EOF
                    break
                if not chunk:
                    break
                bytes_read += len(chunk)
                hash.update(chunk)

        if bytes_read:
            if bytes_read != self.get_file_size(file):
                LOGGER.warning("File %s partially out of iso range. Read %d bytes out of %d bytes",
                               self.get_file_path(file), bytes_read, self.get_file_size(file))
            return hash, self.get_file_size(file) - bytes_read
        elif self.get_file_size(file):
            LOGGER.warning("File %s out of iso range", self.get_file_path(file))
            return None, self.get_file_size(file)

        return hash, 0


