import io
import math
import os

from pycdlib.pycdlibio import PyCdlibIO


class DecryptedFileIO(PyCdlibIO):
    def __init__(self, ino, logical_block_size, buffer_blocks=16):
        super().__init__(ino, logical_block_size)
        self.logical_block_size = logical_block_size
        self.buffer_size = logical_block_size * buffer_blocks
        self._buffer = bytearray(self.buffer_size)
        self._buffer_offset = 0
        self._buffer_filled = 0

    def readinto(self, b):
        readsize = self._length - self._offset
        if readsize <= 0:
            return 0

        mv = memoryview(b)
        m = mv.cast('B')
        readsize = min(readsize, len(m))
        data = self.read(readsize)
        n = len(data)
        m[:n] = data

        return n

    def read(self, size=None):
        offset = self._offset - self._buffer_filled + self._buffer_offset
        if offset >= self._length:
            return b''
        if size is None:
            size = self._length - offset

        read_size = min(size, self._length - offset)
        result = bytearray(read_size)
        bytes_read = 0

        while bytes_read < read_size:
            if self._buffer_offset >= self._buffer_filled:
                self._fill_buffer(read_size - bytes_read)
                if self._buffer_filled == 0:
                    break

            chunk_size = min(self._buffer_filled - self._buffer_offset, read_size - bytes_read)
            result[bytes_read:bytes_read + chunk_size] = self._buffer[
                                                         self._buffer_offset:self._buffer_offset + chunk_size]

            self._buffer_offset += chunk_size
            bytes_read += chunk_size
        return bytes(result)

    def _fill_buffer(self, desired_size):
        # Align to block boundary
        block_offset = self._offset % self.logical_block_size
        aligned_offset = self._offset - block_offset

        if aligned_offset != self._offset:
            super().seek(aligned_offset)

        # Calculate how many full blocks to read
        blocks_to_read = min(
            math.ceil((desired_size + block_offset) / self.logical_block_size),
            self.buffer_size // self.logical_block_size
        )

        data = super().read(blocks_to_read * self.logical_block_size)
        if not data:
            self._buffer_filled = 0
            return

        # If we didn't get a full block (ie. file is smaller than the logical block size), we need to
        # read the rest of the base file to get the rest of the encrypted block
        if len(data) < self.logical_block_size * blocks_to_read:
            read_extra = (self.logical_block_size * blocks_to_read) - len(data)
            # Read the underlying file directly to bypass the length check in read().
            # We need the actual encrypted data and can't just pad with zeroes
            data += self._fp.read(read_extra)
            self._offset += read_extra

        # Decrypt all blocks at once
        decrypted_data = self.decrypt_blocks(data)

        self._buffer[:len(decrypted_data)] = decrypted_data
        self._buffer_filled = len(decrypted_data)
        self._buffer_offset = block_offset

    def seek(self, offset, whence=0):
        new_offset = super().seek(offset, whence)
        self._buffer_offset = 0
        self._buffer_filled = 0
        return new_offset

    def tell(self):
        return super().tell() - self._buffer_filled + self._buffer_offset

    def decrypt_blocks(self, blocks):
        raise NotImplementedError

    def decrypt_block(self, block):
        raise NotImplementedError
