import io


class BaseFile(io.RawIOBase):
    def __init__(self, fp):
        self.fp = fp
        self._pos = 0

    def decrypt_block(self, block_num, decrypt_key):
        raise NotImplementedError

    def readinto(self, b):
        # Determine how many bytes to read
        bytes_to_read = len(b)
        if self._pos + bytes_to_read > self._size:
            bytes_to_read = self._size - self._pos

        if bytes_to_read <= 0:
            return 0

        # Read the data
        data = self.read(bytes_to_read)

        # Copy the data into the provided buffer
        b[:len(data)] = data

        return len(data)

    def read(self, size=-1):
        if size < 0:
            size = self._size - self._pos

        data = bytearray()
        bytes_read = 0
        while bytes_read < size and self._pos < self._size:
            block_num = self._pos // self.edat_header.block_size
            block_offset = self._pos % self.edat_header.block_size
            block_data = self.decrypt_block(block_num, self.edat_key)

            if block_data == -1:
                break

            remaining_in_block = min(len(block_data) - block_offset, self._size - self._pos)
            remaining_to_read = min(size - bytes_read, remaining_in_block)

            chunk = block_data[block_offset:block_offset + remaining_to_read]
            data.extend(chunk)
            self._pos += len(chunk)
            bytes_read += len(chunk)

            if len(chunk) < remaining_to_read:
                break

        return bytes(data)

    def seek(self, offset, whence=io.SEEK_SET):
        if whence == io.SEEK_SET:
            self._pos = offset
        elif whence == io.SEEK_CUR:
            self._pos += offset
        elif whence == io.SEEK_END:
            self._pos = self._size + offset
        self._pos = max(0, min(self._pos, self._size))
        return self._pos

    def tell(self):
        return self._pos

    def readable(self):
        return True

    def writable(self):
        return False

    def seekable(self):
        return True
