import numba
import numpy as np
from typing import Optional, Tuple


@numba.jit(nopython=True)
def decode_range(in_bytes: np.ndarray, src: np.int32, range_val: np.uint32, code: np.uint32) -> Tuple[
    np.int32, np.uint32, np.uint32]:
    """Updates range and code values based on input bytes."""
    if not (range_val >> 24):
        range_val = (range_val << 8) & 0xFFFFFFFF
        code = ((code << 8) & 0xFFFFFFFF) + in_bytes[src + 5]
        src += 1
    return src, range_val, code


@numba.jit(nopython=True)
def decode_bit(in_bytes: np.ndarray, tmp: np.ndarray, src: np.int32, range_val: np.uint32,
               code: np.uint32, tmp_index: np.int32, acc: Optional[np.ndarray] = None) -> Tuple[
    np.int32, np.uint32, np.uint32, np.int32]:
    """Decodes a single bit from the compressed data."""
    src, range_val, code = decode_range(in_bytes, src, range_val, code)

    c = np.uint32(tmp[tmp_index])
    tmp[tmp_index] = np.uint8((c - (c >> 3)) & 0xFF)

    if acc is not None:
        acc[0] = np.int32(acc[0] << 1)

    val = np.uint32((range_val >> 8) * c)

    if code < val:
        range_val = val
        tmp[tmp_index] = np.uint8((tmp[tmp_index] + 31) & 0xFF)
        if acc is not None:
            acc[0] += 1
        return src, range_val, code, 1
    else:
        code -= val
        range_val -= val
        return src, range_val, code, 0


@numba.jit(nopython=True)
def decode_number(in_bytes: np.ndarray, tmp: np.ndarray, src: np.int32, range_val: np.uint32,
                  code: np.uint32, base_offset: np.int32, index_val: np.int32) -> Tuple[
    np.int32, np.uint32, np.uint32, np.int32, np.int32]:
    """Decodes a number from the compressed data."""
    acc = np.array([1], dtype=np.int32)

    if index_val >= 3:
        src, range_val, code, _ = decode_bit(in_bytes, tmp, src, range_val, code, base_offset + 0x18, acc)
        if index_val >= 4:
            src, range_val, code, _ = decode_bit(in_bytes, tmp, src, range_val, code, base_offset + 0x18, acc)
            if index_val >= 5:
                src, range_val, code = decode_range(in_bytes, src, range_val, code)
                for _ in range(index_val - 4):
                    acc[0] = np.int32(acc[0] << 1)
                    range_val >>= 1
                    if code < range_val:
                        acc[0] += 1
                    else:
                        code -= range_val

    src, range_val, code, bit_flag = decode_bit(in_bytes, tmp, src, range_val, code, base_offset, acc)

    if index_val >= 1:
        src, range_val, code, _ = decode_bit(in_bytes, tmp, src, range_val, code, base_offset + 0x8, acc)
        if index_val >= 2:
            src, range_val, code, _ = decode_bit(in_bytes, tmp, src, range_val, code, base_offset + 0x10, acc)

    return src, range_val, code, acc[0], bit_flag


@numba.jit(nopython=True)
def decode_word(in_bytes: np.ndarray, tmp: np.ndarray, src: np.int32, range_val: np.uint32,
                code: np.uint32, base_offset: np.int32, index_val: np.int32) -> Tuple[
    np.int32, np.uint32, np.uint32, np.int32, np.int32]:
    """Decodes a word from the compressed data."""
    index_val = np.int32(index_val // 8)
    acc = np.array([1], dtype=np.int32)

    if index_val >= 3:
        src, range_val, code, _ = decode_bit(in_bytes, tmp, src, range_val, code, base_offset + 4, acc)
        if index_val >= 4:
            src, range_val, code, _ = decode_bit(in_bytes, tmp, src, range_val, code, base_offset + 4, acc)
            if index_val >= 5:
                src, range_val, code = decode_range(in_bytes, src, range_val, code)
                for _ in range(index_val - 4):
                    acc[0] = np.int32(acc[0] << 1)
                    range_val >>= 1
                    if code < range_val:
                        acc[0] += 1
                    else:
                        code -= range_val

    src, range_val, code, bit_flag = decode_bit(in_bytes, tmp, src, range_val, code, base_offset, acc)

    if index_val >= 1:
        src, range_val, code, _ = decode_bit(in_bytes, tmp, src, range_val, code, base_offset + 1, acc)
        if index_val >= 2:
            src, range_val, code, _ = decode_bit(in_bytes, tmp, src, range_val, code, base_offset + 2, acc)

    return src, range_val, code, acc[0], bit_flag


@numba.jit(nopython=True)
def decompress(in_bytes: np.ndarray, out_size: np.int32) -> Optional[np.ndarray]:
    """Decompresses the input data."""
    out = np.zeros(out_size, dtype=np.uint8)
    src = np.int32(0)
    pos = np.int32(0)
    head = np.uint8(in_bytes[0])
    prev = np.uint8(0)
    offset = np.int32(0)
    range_val = np.uint32(0xFFFFFFFF)

    # Construct the 32-bit "code" from bytes 1..4
    code = np.uint32(int(in_bytes[1]) << 24 | int(in_bytes[2]) << 16 | int(in_bytes[3]) << 8 | int(in_bytes[4]))

    # Initialize temporary buffer
    tmp = np.zeros(3272, dtype=np.uint8)
    tmp[:0xCA8] = np.uint8(0x80)

    # Handle uncompressed data
    if head > 0x80:
        length = code
        if length <= out_size:
            out[:length] = in_bytes[5:5 + length]
            return out
        return None

    while pos < out_size:
        sect1_index = offset + 0xB68

        src, range_val, code, bit = decode_bit(in_bytes, tmp, src, range_val, code, sect1_index)

        if bit == 0:
            # Handle raw character
            if offset > 0:
                offset -= 1
            if pos >= out_size:
                return out[:pos]

            sect = np.int32((((((pos & 7) << 8) + prev) >> head) & 7) * 0xFF - 1)
            acc = np.array([1], dtype=np.int32)

            while not (acc[0] >> 8):
                src, range_val, code, _ = decode_bit(in_bytes, tmp, src, range_val, code, sect + acc[0], acc)

            out[pos] = np.uint8(acc[0] & 0xFF)
            pos += 1

        else:
            # Handle compressed stream
            index_val = np.int32(-1)
            sect1 = offset + 0xB68

            while True:
                sect1 += 8
                src, range_val, code, bit = decode_bit(in_bytes, tmp, src, range_val, code, sect1)
                index_val += bit
                if not bit or index_val >= 6:
                    break

            b_size = np.int32(0x160)
            tmp_sect2 = index_val + 0x7F1

            if index_val >= 0 or bit:
                sect = np.int32((index_val << 5) | ((((pos << index_val) & 3) << 3) | (offset & 7)))
                tmp_sect1 = np.int32(0xBA8 + sect)
                src, range_val, code, data_length, _ = decode_number(in_bytes, tmp, src, range_val, code, tmp_sect1,
                                                                     index_val)

                if data_length == 0xFF:
                    return out[:pos]
            else:
                data_length = np.int32(1)

            if data_length <= 2:
                tmp_sect2 += 0xF8
                b_size = np.int32(0x40)

            shift_val = np.array([1], dtype=np.int32)

            while True:
                diff = np.int32((shift_val[0] << 4) - b_size)
                src, range_val, code, bit = decode_bit(in_bytes, tmp, src, range_val, code,
                                                       tmp_sect2 + (shift_val[0] << 3), shift_val)
                if diff >= 0:
                    break

            if diff > 0 or bit:
                if not bit:
                    diff -= 8
                tmp_sect3 = np.int32(0x928 + diff)
                src, range_val, code, data_offset, _ = decode_word(in_bytes, tmp, src, range_val, code, tmp_sect3, diff)
            else:
                data_offset = np.int32(1)

            buf_start = pos - data_offset
            buf_end = pos + data_length + 1

            if buf_start < 0 or buf_end > out_size:
                return None

            offset = np.int32(((buf_end + 1) & 1) + 6)

            for i in range(data_length + 1):
                out[pos] = out[buf_start + i]
                pos += 1

        prev = out[pos - 1]

    return out


def decompress_bytes(in_bytes: bytes, out_size: int) -> Optional[bytes]:
    """Wrapper function to handle bytes input/output"""
    result = decompress(np.frombuffer(in_bytes, dtype=np.uint8), np.int32(out_size))
    if result is not None:
        return bytes(result)
    return None
