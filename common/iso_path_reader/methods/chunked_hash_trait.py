import logging

LOGGER = logging.getLogger(__name__)


class CachedHashResult:
    def __init__(self, digest, hexdigest):
        self._digest = digest
        self._hexdigest = hexdigest

    def digest(self):
        return self._digest

    def hexdigest(self):
        return self._hexdigest


class ChunkedHashTrait:
    def open_file(self, file):
        raise NotImplementedError

    def get_file_size(self, file):
        raise NotImplementedError

    def get_file_path(self, file):
        raise NotImplementedError

    def _file_path(self, file):
        # internal/logging variant; readers whose get_file_path has side
        # effects (namespace recording) override this
        return self.get_file_path(file)

    def get_file_hash(self, file, algo):
        cache_key = None
        if self.extent_cache is not None:
            extents = self.get_file_extents(file)
            if extents is not None:
                # HashProgressWrapper carries the real constructor in hash_class
                cache_key = (extents, getattr(algo, "hash_class", algo))
                cached = self.extent_cache.get(cache_key)
                if cached is not None:
                    digest, hexdigest, unread_bytes = cached
                    if LOGGER.isEnabledFor(logging.DEBUG):
                        LOGGER.debug("Extent cache hit for %s", self._file_path(file))
                    if digest is None:
                        return None, unread_bytes
                    return CachedHashResult(digest, hexdigest), unread_bytes

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
                               self._file_path(file), bytes_read, self.get_file_size(file))
            unread_bytes = self.get_file_size(file) - bytes_read
            if cache_key is not None:
                self.extent_cache[cache_key] = (hash.digest(), hash.hexdigest(), unread_bytes)
            return hash, unread_bytes
        elif self.get_file_size(file):
            LOGGER.warning("File %s out of iso range", self._file_path(file))
            if cache_key is not None:
                self.extent_cache[cache_key] = (None, None, self.get_file_size(file))
            return None, self.get_file_size(file)

        if cache_key is not None:
            self.extent_cache[cache_key] = (hash.digest(), hash.hexdigest(), 0)
        return hash, 0
