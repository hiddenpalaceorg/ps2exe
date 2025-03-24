from dataclasses import dataclass
from typing import Optional, Tuple


@dataclass
class LZDecompressor:
    in_bytes: bytes

    def __init__(self, in_bytes: bytes):
        self.in_bytes = in_bytes
        self.src = 0
        self.range = 0xFFFFFFFF

        # Construct the 32-bit "code" from bytes 1..4
        self.code = int.from_bytes(in_bytes[1:5], byteorder='big')

        # Initialize temporary buffer with 0x80 bytes
        self.tmp = bytearray([0x80] * 0xCA8 + [0] * (3272 - 0xCA8))

    def decode_range(self) -> None:
        """Updates range and code values based on input bytes."""
        if not (self.range >> 24):
            self.range = (self.range << 8) & 0xFFFFFFFF
            self.code = ((self.code << 8) & 0xFFFFFFFF) + self.in_bytes[self.src + 5]
            self.src += 1

    def decode_bit(self, acc: Optional[list], tmp_index: int) -> int:
        """
        Decodes a single bit from the compressed data.

        Args:
            acc: Optional accumulator list containing a single value
            tmp_index: Index into temporary buffer

        Returns:
            Decoded bit (0 or 1)
        """
        self.decode_range()

        c = self.tmp[tmp_index]
        self.tmp[tmp_index] = (c - (c >> 3)) & 0xFF

        if acc is not None:
            acc[0] <<= 1

        val = (self.range >> 8) * c

        if self.code < val:
            self.range = val
            self.tmp[tmp_index] = (self.tmp[tmp_index] + 31) & 0xFF
            if acc is not None:
                acc[0] += 1
            return 1
        else:
            self.code -= val
            self.range -= val
            return 0

    def decode_number(self, base_offset: int, index_val: int) -> Tuple[int, int]:
        """
        Decodes a number from the compressed data.

        Args:
            base_offset: Offset into temporary buffer
            index_val: Index value from caller

        Returns:
            Tuple of (decoded number, bit flag)
        """
        acc = [1]

        # Handle higher index values
        if index_val >= 3:
            self.decode_bit(acc, base_offset + 0x18)
            if index_val >= 4:
                self.decode_bit(acc, base_offset + 0x18)
                if index_val >= 5:
                    self.decode_range()
                    for _ in range(index_val - 4):
                        acc[0] <<= 1
                        self.range >>= 1
                        if self.code < self.range:
                            acc[0] += 1
                        else:
                            self.code -= self.range

        bit_flag = self.decode_bit(acc, base_offset)

        # Handle lower index values
        if index_val >= 1:
            self.decode_bit(acc, base_offset + 0x8)
            if index_val >= 2:
                self.decode_bit(acc, base_offset + 0x10)

        return acc[0], bit_flag

    def decode_word(self, base_offset: int, index_val: int) -> Tuple[int, int]:
        """
        Decodes a word from the compressed data.

        Args:
            base_offset: Offset into temporary buffer
            index_val: Index value divided by 8

        Returns:
            Tuple of (decoded word, bit flag)
        """
        index_val //= 8
        acc = [1]

        if index_val >= 3:
            self.decode_bit(acc, base_offset + 4)
            if index_val >= 4:
                self.decode_bit(acc, base_offset + 4)
                if index_val >= 5:
                    self.decode_range()
                    for _ in range(index_val - 4):
                        acc[0] <<= 1
                        self.range >>= 1
                        if self.code < self.range:
                            acc[0] += 1
                        else:
                            self.code -= self.range

        bit_flag = self.decode_bit(acc, base_offset)

        if index_val >= 1:
            self.decode_bit(acc, base_offset + 1)
            if index_val >= 2:
                self.decode_bit(acc, base_offset + 2)

        return acc[0], bit_flag

    def decompress(self, out_size: int) -> Optional[bytes]:
        """
        Decompresses the input data.

        Args:
            out_size: Expected size of decompressed output

        Returns:
            Decompressed data as bytes, or None if decompression fails
        """
        out = bytearray(out_size)
        pos = 0
        head = self.in_bytes[0]
        prev = 0
        offset = 0

        # Handle uncompressed data
        if head > 0x80:
            length = self.code
            if length <= out_size:
                out[:length] = self.in_bytes[5:5 + length]
                return bytes(out)
            return None

        while pos < out_size:
            sect1_index = offset + 0xB68

            if self.decode_bit(None, sect1_index) == 0:
                # Handle raw character
                if offset > 0:
                    offset -= 1
                if pos >= out_size:
                    return bytes(out[:pos])

                sect = (((((pos & 7) << 8) + prev) >> head) & 7) * 0xFF - 1
                acc = [1]

                while not (acc[0] >> 8):
                    self.decode_bit(acc, sect + acc[0])

                out[pos] = acc[0] & 0xFF
                pos += 1

            else:
                # Handle compressed stream
                index_val = -1
                sect1 = offset + 0xB68

                while True:
                    sect1 += 8
                    bit = self.decode_bit(None, sect1)
                    index_val += bit
                    if not bit or index_val >= 6:
                        break

                b_size = 0x160
                tmp_sect2 = index_val + 0x7F1

                if index_val >= 0 or bit:
                    sect = (index_val << 5) | ((((pos << index_val) & 3) << 3) | (offset & 7))
                    tmp_sect1 = 0xBA8 + sect
                    data_length, _ = self.decode_number(tmp_sect1, index_val)

                    if data_length == 0xFF:
                        return bytes(out[:pos])
                else:
                    data_length = 1

                if data_length <= 2:
                    tmp_sect2 += 0xF8
                    b_size = 0x40

                shift_val = [1]

                while True:
                    diff = (shift_val[0] << 4) - b_size
                    bit = self.decode_bit(shift_val, tmp_sect2 + (shift_val[0] << 3))
                    if diff >= 0:
                        break

                if diff > 0 or bit:
                    if not bit:
                        diff -= 8
                    tmp_sect3 = 0x928 + diff
                    data_offset, _ = self.decode_word(tmp_sect3, diff)
                else:
                    data_offset = 1

                buf_start = pos - data_offset
                buf_end = pos + data_length + 1

                if buf_start < 0 or buf_end > out_size:
                    return None

                offset = (((buf_end + 1) & 1) + 6)

                for i in range(data_length + 1):
                    out[pos] = out[buf_start + i]
                    pos += 1

            prev = out[pos - 1]

        return bytes(out)
