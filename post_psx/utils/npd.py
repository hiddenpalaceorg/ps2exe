import io
import struct

from Crypto.Cipher import AES
from Crypto.Hash import CMAC, SHA1, HMAC

from post_psx.types import NPDHeader, EDATHeader
from post_psx.utils import lz
from post_psx.utils.base import BaseFile


class NPDFile(BaseFile):
    SDAT_FLAG = 0x01000000
    EDAT_COMPRESSED_FLAG = 0x00000001
    EDAT_FLAG_0x02 = 0x00000002
    EDAT_ENCRYPTED_KEY_FLAG = 0x00000008
    EDAT_FLAG_0x10 = 0x00000010
    EDAT_FLAG_0x20 = 0x00000020
    EDAT_DEBUG_DATA_FLAG = 0x80000000

    SDAT_KEY = bytearray([0x0D, 0x65, 0x5E, 0xF8, 0xE6, 0x74, 0xA9, 0x8A,
                          0xB8, 0x50, 0x5C, 0xFA, 0x7D, 0x01, 0x29, 0x33])
    NP_OMAC_KEY_2 = bytearray([0x6B, 0xA5, 0x29, 0x76, 0xEF, 0xDA, 0x16, 0xEF,
                               0x3C, 0x33, 0x9F, 0xB2, 0x97, 0x1E, 0x25, 0x6B])
    NP_OMAC_KEY_3 = bytearray([0x9B, 0x51, 0x5F, 0xEA, 0xCF, 0x75, 0x06, 0x49,
                               0x81, 0xAA, 0x60, 0x4D, 0x91, 0xA5, 0x4E, 0x97])
    RAP_KEY = bytearray([0x86, 0x9F, 0x77, 0x45, 0xC1, 0x3F, 0xD8, 0x90,
                         0xCC, 0xF2, 0x91, 0x88, 0xE3, 0xCC, 0x3E, 0xDF])
    RAP_PBOX = bytearray([0x0C, 0x03, 0x06, 0x04, 0x01, 0x0B, 0x0F, 0x08,
                          0x02, 0x07, 0x00, 0x05, 0x0A, 0x0E, 0x0D, 0x09])
    RAP_E1 = bytearray([0xA9, 0x3E, 0x1F, 0xD6, 0x7C, 0x55, 0xA3, 0x29,
                        0xB7, 0x5F, 0xDD, 0xA6, 0x2A, 0x95, 0xC7, 0xA5])
    RAP_E2 = bytearray([0x67, 0xD4, 0x5D, 0xA3, 0x29, 0x6D, 0x00, 0x6A,
                        0x4E, 0x7C, 0x53, 0x7B, 0xF5, 0x53, 0x8C, 0x74])
    EDAT_KEY_0 = bytearray([0xBE, 0x95, 0x9C, 0xA8, 0x30, 0x8D, 0xEF, 0xA2,
                            0xE5, 0xE1, 0x80, 0xC6, 0x37, 0x12, 0xA9, 0xAE])
    EDAT_HASH_0 = bytearray([0xEF, 0xFE, 0x5B, 0xD1, 0x65, 0x2E, 0xEB, 0xC1,
                             0x19, 0x18, 0xCF, 0x7C, 0x04, 0xD4, 0xF0, 0x11])
    EDAT_KEY_1 = bytearray([0x4C, 0xA9, 0xC1, 0x4B, 0x01, 0xC9, 0x53, 0x09,
                            0x96, 0x9B, 0xEC, 0x68, 0xAA, 0x0B, 0xC0, 0x81])
    EDAT_HASH_1 = bytearray([0x3D, 0x92, 0x69, 0x9B, 0x70, 0x5B, 0x07, 0x38,
                             0x54, 0xD8, 0xFC, 0xC6, 0xC7, 0x67, 0x27, 0x47])
    NP_KLIC_FREE = bytearray([0x72, 0xF9, 0x90, 0x78, 0x8F, 0x9C, 0xFF, 0x74, 0x57, 0x25, 0xF0, 0x8E, 0x4C, 0x12, 0x83, 0x87])

    EDAT_IV = bytearray(0x10)

    def __init__(self, fp, file_name, edat_key):
        super().__init__(fp)
        self.fp.seek(0)
        self.npd_header = NPDHeader.unpack(fp.read(NPDHeader.struct.size))
        self.fp.seek(0x80)
        edh = self.fp.read(EDATHeader.struct.size)
        self.edat_header = EDATHeader.unpack(edh)
        self.edat_key = edat_key
        self._pos = 0
        self._size = self.edat_header.file_size
        self.total_blocks = -(self._size // -self.edat_header.block_size)

        self.hash_key = int.from_bytes(self.npd_header.dev_hash, byteorder="little")
        if self.edat_header.flags & self.SDAT_FLAG:
            self.hash_key ^= int.from_bytes(self.SDAT_KEY, byteorder="little")

    @classmethod
    def rap_to_rif(cls, rap):
        key = bytearray(0x10)
        iv = bytearray(0x10)

        # Initial decrypt.
        aes = AES.new(cls.RAP_KEY, AES.MODE_CBC, iv)
        key[:] = aes.decrypt(rap)

        # rap2rifkey round.
        for _ in range(5):
            for i in range(16):
                p = cls.RAP_PBOX[i]
                key[p] ^= cls.RAP_E1[p]

            for i in range(15, 0, -1):
                p = cls.RAP_PBOX[i]
                pp = cls.RAP_PBOX[i - 1]
                key[p] ^= key[pp]

            o = 0
            for i in range(16):
                p = cls.RAP_PBOX[i]
                kc = (key[p] - o) & 0xFF  # Ensure the subtraction is done modulo 256
                ec2 = cls.RAP_E2[p]
                if o != 1 or kc != 0xFF:
                    o = 1 if kc < ec2 else 0
                    key[p] = (kc - ec2) & 0xFF
                else:
                    key[p] = (kc - ec2) & 0xFF

        return bytes(key)

    def validate_npd_hashes(self, file_name):
        if self.edat_header.flags & self.EDAT_DEBUG_DATA_FLAG:
            return True

        if not self.validate_dev_klic(self.edat_key):
            return False

        # Build the title buffer (content_id + file_name).
        buf = bytearray(self.npd_header.content_id[:0x30] + file_name.encode('utf-8'))
        buf_lower = bytearray(buf)
        buf_upper = bytearray(buf)

        dot_index = file_name.rfind('.')
        if dot_index != -1:
            buf_lower = buf[0:-dot_index] + buf[-dot_index:].lower()
            buf_upper = buf[0:-dot_index] + buf[-dot_index:].lower()

        # Hash with NPDRM_OMAC_KEY_3 and compare with title_hash.
        # Try to ignore case sensitivity with file extension
        def cmac_compare(buffer):
            c = CMAC.new(self.NP_OMAC_KEY_3, ciphermod=AES)
            c.update(buffer)
            return c.digest() == self.npd_header.title_hash

        title_hash_result = (
                cmac_compare(buf) or
                cmac_compare(buf_lower) or
                cmac_compare(buf_upper)
        )

        return title_hash_result

    def validate_dev_klic2(self, dec_key):
        if (self.npd_header.license & 0x3) != 0x3:
            return True

        dev = bytearray(0x60)

        # Build the dev buffer (first 0x60 bytes of NPD header in big-endian).
        dev[:0x60] = self.npd_header.pack()[:0x60]

        # Fix endianness.
        version = struct.unpack('>i', struct.pack('<i', self.npd_header.version))[0]
        license = struct.unpack('>i', struct.pack('<i', self.npd_header.license))[0]
        app_type = struct.unpack('>i', struct.pack('<i', self.npd_header.app_type))[0]

        dev[0x4:0x8] = struct.pack('>i', version)
        dev[0x8:0xC] = struct.pack('>i', license)
        dev[0xC:0x10] = struct.pack('>i', app_type)

        # Check for an empty dev_hash (can't validate if devklic is NULL).
        klic = dec_key

        # Generate klicensee xor key.
        key = klic ^ int.from_bytes(self.NP_OMAC_KEY_2, byteorder='big')

        # Hash with generated key and compare with dev_hash.
        key_bytes = key.to_bytes(16, byteorder='big')
        c = CMAC.new(key_bytes, ciphermod=AES)
        c.update(dev[:0x60])
        generated_hash = c.digest()

        return generated_hash == self.npd_header.dev_hash

    def validate_dev_klic(self, dec_key):
        if (self.npd_header.license & 0x3) != 0x3:
            return True

        if not dec_key:
            return False

        dev = bytearray(0x60)

        # Build the dev buffer (first 0x60 bytes of NPD header in big-endian)
        dev[:0x60] = self.npd_header.pack()[:0x60]

        # Fix endianness
        version = struct.pack('>I', self.npd_header.version)
        license = struct.pack('>I', self.npd_header.license)
        app_type = struct.pack('>I',  self.npd_header.app_type)
        dev[0x4:0x8] = version
        dev[0x8:0xC] = license
        dev[0xC:0x10] = app_type

        # Generate klicensee xor key
        key = bytes(a ^ b for a, b in zip(dec_key, self.NP_OMAC_KEY_2))

        # Hash with generated key and compare with dev_hash.
        key_bytes = key
        c = CMAC.new(key_bytes, ciphermod=AES)
        c.update(dev[:0x60])
        generated_hash = c.digest()

        # Hash with generated key and compare with dev_hash
        return generated_hash == self.npd_header.dev_hash

    @staticmethod
    def dec_section(metadata: bytes):
        dec = bytearray(16)
        dec[0x00] = metadata[0xC] ^ metadata[0x8] ^ metadata[0x10]
        dec[0x01] = metadata[0xD] ^ metadata[0x9] ^ metadata[0x11]
        dec[0x02] = metadata[0xE] ^ metadata[0xA] ^ metadata[0x12]
        dec[0x03] = metadata[0xF] ^ metadata[0xB] ^ metadata[0x13]
        dec[0x04] = metadata[0x4] ^ metadata[0x8] ^ metadata[0x14]
        dec[0x05] = metadata[0x5] ^ metadata[0x9] ^ metadata[0x15]
        dec[0x06] = metadata[0x6] ^ metadata[0xA] ^ metadata[0x16]
        dec[0x07] = metadata[0x7] ^ metadata[0xB] ^ metadata[0x17]
        dec[0x08] = metadata[0xC] ^ metadata[0x0] ^ metadata[0x18]
        dec[0x09] = metadata[0xD] ^ metadata[0x1] ^ metadata[0x19]
        dec[0x0A] = metadata[0xE] ^ metadata[0x2] ^ metadata[0x1A]
        dec[0x0B] = metadata[0xF] ^ metadata[0x3] ^ metadata[0x1B]
        dec[0x0C] = metadata[0x4] ^ metadata[0x0] ^ metadata[0x1C]
        dec[0x0D] = metadata[0x5] ^ metadata[0x1] ^ metadata[0x1D]
        dec[0x0E] = metadata[0x6] ^ metadata[0x2] ^ metadata[0x1E]
        dec[0x0F] = metadata[0x7] ^ metadata[0x3] ^ metadata[0x1F]

        # Convert the 'dec' array to the appropriate types
        offset = struct.unpack('>Q', dec[0:8])[0]
        length = struct.unpack('>i', dec[8:12])[0]
        compression_end = struct.unpack('>i', dec[12:16])[0]

        return offset, length, compression_end

    def decrypt_block(self, block_num, decrypt_key):
        if (self.edat_header.flags & self.EDAT_COMPRESSED_FLAG != 0) or (self.edat_header.flags & self.EDAT_FLAG_0x20 != 0):
            metadata_section_size = 0x20
        else:
            metadata_section_size = 0x10
        metadata_offset = 0x100

        # Initialize buffers
        hash_ = bytearray(0x10)
        hash_result = bytearray(0x14)
        empty_iv = bytes(0x10)

        compression_end = None

        # Decrypt the metadata
        if self.edat_header.flags & self.EDAT_COMPRESSED_FLAG:
            metadata_sec_offset = metadata_offset + block_num * metadata_section_size
            self.fp.seek(metadata_sec_offset)
            metadata = self.fp.read(0x20)

            # If the data is compressed, decrypt the metadata.
            # NOTE: For NPD version 1 the metadata is not encrypted.
            if self.npd_header.version <= 1:
                offset, length, compression_end = struct.unpack('>Qii', metadata[0x10:0x20])
            else:
                offset, length, compression_end = self.dec_section(metadata)

            hash_result[:0x10] = metadata[:0x10]
        elif self.edat_header.flags & self.EDAT_FLAG_0x20:
            # If FLAG 0x20, the metadata precedes each data block.
            metadata_sec_offset = metadata_offset + block_num * (metadata_section_size + self.edat_header.block_size)
            self.fp.seek(metadata_sec_offset)
            metadata = self.fp.read(0x20)
            hash_result[:] = metadata[:0x14]

            # Apply custom XOR if FLAG 0x20 is set
            for j in range(0x10):
                hash_result[j] ^= metadata[j + 0x10]

            offset = metadata_sec_offset + 0x20
            length = self.edat_header.block_size

            if block_num == self.total_blocks - 1 and self.edat_header.file_size % self.edat_header.block_size:
                length = self.edat_header.file_size % self.edat_header.block_size

        else:
            metadata_sec_offset = metadata_offset + block_num * metadata_section_size
            self.fp.seek(metadata_sec_offset)
            hash_result[:0x10] = self.fp.read(0x10)

            offset = metadata_offset + block_num * self.edat_header.block_size + self.total_blocks * metadata_section_size
            length = self.edat_header.block_size

            if block_num == self.total_blocks - 1 and self.edat_header.file_size % self.edat_header.block_size:
                length = self.edat_header.file_size % self.edat_header.block_size

        pad_length = length
        length = (length + 0x10 - 1) // 0x10 * 0x10

        # Prepare decryption buffers
        self.fp.seek(offset)
        enc_data = self.fp.read(length)
        if len(enc_data) != length:
            return -1
        dec_data = io.BytesIO()

        b_key = self.get_block_key(block_num)
        cipher = AES.new(decrypt_key, AES.MODE_ECB)
        key_result = cipher.encrypt(b_key)

        if self.edat_header.flags & self.EDAT_FLAG_0x10:
            hash_[:0x10] = cipher.encrypt(key_result)
        else:
            hash_[:0x10] = key_result

        crypto_mode = 0x2 if not self.edat_header.flags & self.EDAT_FLAG_0x02 else 0x1
        hash_mode = 0x02 if not self.edat_header.flags & self.EDAT_FLAG_0x10 else (
            0x04 if not self.edat_header.flags & self.EDAT_FLAG_0x20 else 0x01)

        if self.edat_header.flags & self.EDAT_ENCRYPTED_KEY_FLAG:
            crypto_mode |= 0x10000000
            hash_mode |= 0x10000000

        should_decompress = self.edat_header.flags & self.EDAT_COMPRESSED_FLAG and compression_end

        if self.edat_header.flags & self.EDAT_DEBUG_DATA_FLAG:
            # Already decrypted, just copy the data
            dec_data = io.BytesIO(enc_data if not should_decompress else bytearray(enc_data))
        else:
            # Setup IV and perform decryption
            iv = empty_iv if self.npd_header.version <= 1 else self.npd_header.digest
            if not self.decrypt(
                    hash_mode,
                    crypto_mode,
                    self.npd_header.version == 4,
                    enc_data,
                    dec_data,
                    length,
                    key_result,
                    iv,
                    hash_,
                    hash_result
            ):
                return -1

        # Handle decompression if needed
        if should_decompress:
            res = lz.decompress_bytes(dec_data.getvalue(), self.edat_header.block_size, version=2)

            if not res:
                return -1

            return res

        # Copy the decrypted data to output buffer if necessary
        return dec_data.getvalue()

    def get_block_key(self, block):
        empty_key = bytes(0x10)
        src_key = empty_key if self.npd_header.version <= 1 else self.npd_header.dev_hash
        dest_key = bytearray(0x10)

        # Copy the first 12 bytes from src_key to dest_key
        dest_key[:0xC] = src_key[:0xC]

        # Convert block number to big-endian and store it in the last 4 bytes of dest_key
        swapped_block = struct.pack('>i', block)
        dest_key[0xC:0x10] = swapped_block

        return dest_key

    def decrypt(self, hash_mode, crypto_mode, version, in_data, out_data, length, key, iv, enc_hash, test_hash):
        # Setup buffers for key, iv, and hash.
        key_final = bytearray(0x10)
        iv_final = bytearray(0x10)

        # Generate the crypto key
        mode = crypto_mode & 0xF0000000
        if mode == 0x10000000:
            # Encrypted ERK
            temp_iv = bytearray(self.EDAT_IV)
            cipher = AES.new(self.EDAT_KEY_1 if version else self.EDAT_KEY_0, AES.MODE_CBC, temp_iv)
            key_final[:] = cipher.decrypt(key)
            iv_final[:] = iv
        elif mode == 0x20000000:
            # Default ERK
            key_final[:] = self.EDAT_KEY_1 if version else self.EDAT_KEY_0
            iv_final[:] = self.EDAT_IV
        elif mode == 0x00000000:
            # Unencrypted ERK
            key_final[:] = key
            iv_final[:] = iv

        # Generate the hash
        mode = hash_mode & 0xF0000000
        hash_len = 0x14 if hash_mode & 0xFF == 0x01 else 0x10
        hash_final = bytearray(hash_len)
        if mode == 0x10000000:
            # Encrypted HASH
            temp_iv = bytearray(self.EDAT_IV)
            cipher = AES.new(self.EDAT_KEY_1 if version else self.EDAT_KEY_0, AES.MODE_CBC, temp_iv)
            hash_final[:] = cipher.decrypt(enc_hash)
        elif mode == 0x20000000:
            # Default HASH
            hash_final[:] = self.EDAT_HASH_1 if version else self.EDAT_HASH_0
        elif mode == 0x00000000:
            # Unencrypted HASH
            hash_final[:] = enc_hash

        # Perform decryption or copying
        if (crypto_mode & 0xFF) == 0x01:
            out_data.write(in_data[:length])
        elif (crypto_mode & 0xFF) == 0x02:
            cipher = AES.new(key_final, AES.MODE_CBC, iv_final)
            out_data.write(cipher.decrypt(in_data[:length]))
        else:
            print("Unknown crypto algorithm!")
            return False

        # Verify the hash
        if (hash_mode & 0xFF) == 0x01:  # 0x14 SHA1-HMAC
            h = HMAC.new(hash_final, digestmod=SHA1)
            h.update(in_data)
            return h.digest() == test_hash[:hash_len]
        elif (hash_mode & 0xFF) == 0x02:  # 0x10 AES-CMAC
            c = CMAC.new(hash_final, ciphermod=AES)
            c.update(in_data)
            return c.digest() == test_hash[:hash_len]
        elif (hash_mode & 0xFF) == 0x04:  # 0x10 SHA1-HMAC
            h = HMAC.new(hash_final, digestmod=SHA1)
            h.update(in_data)
            return h.digest() == test_hash[:hash_len]
        else:
            print("Unknown hashing algorithm!")
            return False

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
