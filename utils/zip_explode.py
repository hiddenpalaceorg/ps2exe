"""
Python implementation of PKZIP's imploded compression method (method id 6)
Ported from apache commons
"""
import io

from bitarray import bitarray
from bitarray.util import ba2int


class CircularBuffer:
    def __init__(self, size):
        self.size = size
        self.buffer = bytearray(size)
        self.read_index = 0
        self.write_index = 0

    def available(self):
        return self.read_index != self.write_index

    def copy(self, distance, length):
        pos1 = self.write_index - distance
        for i in range(length):
            self.buffer[self.write_index] = self.buffer[(pos1 + i) % self.size]
            self.write_index = (self.write_index + 1) % self.size

    def get(self):
        if self.available():
            value = self.buffer[self.read_index]
            self.read_index = (self.read_index + 1) % self.size
            return value
        return -1

    def put(self, value):
        self.buffer[self.write_index] = value
        self.write_index = (self.write_index + 1) % self.size


class BitStream:
    def __init__(self, in_stream):
        self.stream = in_stream
        self.bits = bitarray(endian='little')
        self.bits.fromfile(in_stream)
        self.index = 0

    def next_bit(self):
        if self.index < len(self.bits):
            result = self.bits[self.index]
            self.index += 1
            return int(result)
        return -1

    def next_bits(self, n):
        if self.index + n <= len(self.bits):
            result = ba2int(self.bits[self.index:self.index + n])
            self.index += n
            return result
        return -1

    def next_byte(self):
        return self.next_bits(8)

    def get_bytes_read(self):
        return self.index // 8


class BinaryTree:
    UNDEFINED = -1  # Value indicating an undefined node
    NODE = -2  # Value indicating a non-leaf node

    @staticmethod
    def decode(input_stream, total_number_of_values):
        if total_number_of_values < 0:
            raise ValueError(f"totalNumberOfValues must be bigger than 0, is {total_number_of_values}")

        size = input_stream.read(1)[0] + 1
        if size == 0:
            raise IOError("Cannot read the size of the encoded tree, unexpected end of stream")

        encoded_tree = input_stream.read(size)
        if len(encoded_tree) != size:
            raise EOFError()

        max_length = 0
        original_bit_lengths = [0] * total_number_of_values
        pos = 0

        for b in encoded_tree:
            number_of_values = ((b & 0xF0) >> 4) + 1
            if pos + number_of_values > total_number_of_values:
                raise IOError("Number of values exceeds given total number of values")

            bit_length = (b & 0x0F) + 1
            for j in range(number_of_values):
                original_bit_lengths[pos] = bit_length
                pos += 1

            max_length = max(max_length, bit_length)

        o_bit_lengths = len(original_bit_lengths)
        permutation = list(range(o_bit_lengths))

        sorted_bit_lengths = [0] * o_bit_lengths
        c = 0

        for k in range(o_bit_lengths):
            for l in range(o_bit_lengths):
                if original_bit_lengths[l] == k:
                    sorted_bit_lengths[c] = k
                    permutation[c] = l
                    c += 1

        code = 0
        code_increment = 0
        last_bit_length = 0
        codes = [0] * total_number_of_values

        for i in range(total_number_of_values - 1, -1, -1):
            code += code_increment
            if sorted_bit_lengths[i] != last_bit_length:
                last_bit_length = sorted_bit_lengths[i]
                code_increment = 1 << (16 - last_bit_length)
            codes[permutation[i]] = code

        tree = BinaryTree(max_length)

        for k in range(len(codes)):
            bit_length = original_bit_lengths[k]
            if bit_length > 0:
                tree.add_leaf(0, int('{:016b}'.format(codes[k])[::-1], 2), bit_length, k)

        return tree

    def __init__(self, depth):
        if depth < 0 or depth > 30:
            raise ValueError(f"depth must be bigger than 0 and not bigger than 30, but is {depth}")
        self.tree = [BinaryTree.UNDEFINED] * ((1 << (depth + 1)) - 1)

    def add_leaf(self, node, path, depth, value):
        if depth == 0:
            if self.tree[node] != BinaryTree.UNDEFINED:
                raise ValueError(f"Tree value at index {node} has already been assigned ({self.tree[node]})")
            self.tree[node] = value
        else:
            self.tree[node] = BinaryTree.NODE
            next_child = 2 * node + 1 + (path & 1)
            self.add_leaf(next_child, path >> 1, depth - 1, value)

    def read(self, stream):
        current_index = 0

        while True:
            bit = stream.next_bit()
            if bit == -1:
                return -1

            child_index = 2 * current_index + 1 + bit
            value = self.tree[child_index]
            if value == BinaryTree.NODE:
                current_index = child_index
            elif value != BinaryTree.UNDEFINED:
                return value
            else:
                raise IOError(f"The child {bit} of node at index {current_index} is not defined")


class ExplodingInputStream(io.RawIOBase):
    def __init__(self, dictionary_size, number_of_trees, input_stream):
        if dictionary_size not in [4096, 8192]:
            raise ValueError("The dictionary size must be 4096 or 8192")
        if number_of_trees not in [2, 3]:
            raise ValueError("The number of trees must be 2 or 3")

        self.dictionary_size = dictionary_size
        self.number_of_trees = number_of_trees
        self.minimum_match_length = number_of_trees
        self.input_stream = input_stream
        self.bits = None
        self.literal_tree = None
        self.length_tree = None
        self.distance_tree = None
        self.buffer = CircularBuffer(32 * 1024)
        self.uncompressed_count = 0
        self.tree_sizes = 0
        self.end_of_stream = False

    def close(self):
        pass

    def fill_buffer(self):
        self.init()

        bit = self.bits.next_bit()
        if bit == -1:
            self.end_of_stream = True
            return  # EOF

        if bit == 1:
            # literal value
            if self.literal_tree:
                literal = self.literal_tree.read(self.bits)
            else:
                literal = self.bits.next_byte()

            if literal == -1:
                self.end_of_stream = True
                return  # EOF

            self.buffer.put(literal)

        else:
            # back reference
            distance_low_size = 6 if self.dictionary_size == 4096 else 7
            distance_low = int(self.bits.next_bits(distance_low_size))
            distance_high = self.distance_tree.read(self.bits)

            if distance_high == -1 and distance_low <= 0:
                self.end_of_stream = True
                return  # EOF

            distance = (distance_high << distance_low_size) | distance_low

            length = self.length_tree.read(self.bits)
            if length == 63:
                next_byte = self.bits.next_bits(8)
                if next_byte == -1:
                    self.end_of_stream = True
                    return  # EOF
                length += next_byte

            length += self.minimum_match_length
            self.buffer.copy(distance + 1, length)

    def init(self):
        if self.bits is None:
            if self.number_of_trees == 3:
                self.literal_tree = BinaryTree.decode(self.input_stream, 256)

            self.length_tree = BinaryTree.decode(self.input_stream, 64)
            self.distance_tree = BinaryTree.decode(self.input_stream, 64)
            self.tree_sizes += self.input_stream.tell()

            self.bits = BitStream(self.input_stream)

    def read(self, size=None):
        if size is None:
            size = self.buffer.size

        output = bytearray()
        while len(output) < size:
            if not self.buffer.available():
                self.fill_buffer()
                if self.end_of_stream:
                    break

            value = self.buffer.get()
            if value == -1:
                break  # EOF reached
            output.append(value)

        if not output and self.end_of_stream:
            return b''  # End of stream
        return bytes(output)

    def readable(self):
        return True
