import io
import struct

import numpy as np
from Crypto.Cipher import AES
from Crypto.Hash import CMAC

from post_psx.types import PBPHeader, NPUMDImg, PSARBlockInfo, PS1TableEntry, \
    PSTitleImgHeader, CueEntry
from post_psx.utils.base import BaseFile
from post_psx.utils.lz import decompress_bytes
from post_psx.utils.pgd import PGDFile
from utils.in_memory_rollover_temp_file import InMemoryRolloverTempFile


class EbootPBPFile(PGDFile, BaseFile):
    ISO_SECTOR_SIZE = 2048

    # Kirk7 keys
    kirk7_key38 = bytes(
        [0x12, 0x46, 0x8d, 0x7e, 0x1c, 0x42, 0x20, 0x9b, 0xba, 0x54, 0x26, 0x83, 0x5e, 0xb0, 0x33, 0x03])
    kirk7_key39 = bytes(
        [0xc4, 0x3b, 0xb6, 0xd6, 0x53, 0xee, 0x67, 0x49, 0x3e, 0xa9, 0x5f, 0xbc, 0x0c, 0xed, 0x6f, 0x8a])
    kirk7_key63 = bytes(
        [0x9c, 0x9b, 0x13, 0x72, 0xf8, 0xc6, 0x40, 0xcf, 0x1c, 0x62, 0xf5, 0xd5, 0x92, 0xdd, 0xb5, 0x82])

    # PSP AM hash keys
    amctl_hashkey_3 = bytes(
        [0xe3, 0x50, 0xed, 0x1d, 0x91, 0x0a, 0x1f, 0xd0, 0x29, 0xbb, 0x1c, 0x3e, 0xf3, 0x40, 0x77, 0xfb])
    amctl_hashkey_4 = bytes(
        [0x13, 0x5f, 0xa4, 0x7c, 0xab, 0x39, 0x5b, 0xa4, 0x76, 0xb8, 0xcc, 0xa9, 0x8f, 0x3a, 0x04, 0x45])
    amctl_hashkey_5 = bytes(
        [0x67, 0x8d, 0x7f, 0xa3, 0x2a, 0x9c, 0xa0, 0xd1, 0x50, 0x8a, 0xd8, 0x38, 0x5e, 0x4b, 0x01, 0x7e])


    def __init__(self, fp, disc_num=0):
        super().__init__(fp)
        self.size = None
        self.psp_iv = None
        self.psp_key = None
        self.pbp_header: PBPHeader
        self.iso_table_offset: int
        self.total_blocks: int
        self.npudimg: NPUMDImg
        self.iso_disc_map: PSTitleImgHeader
        self.decrypted_buf: InMemoryRolloverTempFile
        self.disc_offsets = []
        self.disc_tables = []
        self.disc_sizes = []
        self.blocks_read = 0
        self.bytes_written = 0
        self.type = None
        self.iso_block_size = 0
        self.iso_base_offset = 0
        self.num_discs = 1
        self.disc_num = disc_num

    def load_header(self):
        self.fp.seek(0)
        self.pbp_header = PBPHeader.unpack(self.fp.read(PBPHeader.struct.size))
        if not self.pbp_header.check_magic():
            return False

        self.fp.seek(self.pbp_header.psar_offset)
        psar_magic = self.fp.read(8)
        if psar_magic == b"NPUMDIMG":
            self.type = 2
            self.fp.seek(self.pbp_header.psar_offset)
            npumdimg_raw = bytearray(self.fp.read(NPUMDImg.struct.size))

            self.npudimg = NPUMDImg.unpack(npumdimg_raw)
            if not self.npudimg.check_magic():
                return False

            if self.npudimg.iso_block_size > 16:
                return False

            self.iso_block_size = self.npudimg.iso_block_size * 2048

            # Calculate CMAC and initialize PSP decryption
            cmac = CMAC.new(self.kirk7_key38, ciphermod=AES)
            cmac.update(npumdimg_raw[:0xc0])
            mac = cmac.digest()
            self.psp_key, self.psp_iv = self.init_psp_decrypt(1, mac, npumdimg_raw, 0xc0, 0xa0)

            # Decrypt additional PSAR header info
            dec_header = self.aes128_psp_decrypt(self.psp_key, self.psp_iv, 0, npumdimg_raw[0x40:0xa0], 0x60)
            npumdimg_raw[0x40:0xa0] = dec_header

            npudimg = NPUMDImg.unpack(npumdimg_raw)

            # Extract ISO information
            iso_total = npudimg.lba_end - npudimg.lba_start
            self.total_blocks = (iso_total + npudimg.iso_block_size - 1) // npudimg.iso_block_size
            self.size = self._size = (npudimg.lba_end + 1) * 2048
            self.iso_table_offset = npudimg.np_table_offset

            # Cache the iso table
            self.fp.seek(self.pbp_header.psar_offset + self.iso_table_offset)
            self.iso_table = io.BytesIO(self.fp.read(self.total_blocks * 32))

        elif psar_magic in [b"PSISOIMG", b"PSTITLEI"]:
            self.type = 1
            self.iso_block_size = 0x9300
            self.iso_base_offset = 0x100000

            if psar_magic == b"PSISOIMG":
                self.num_discs = 1
                self.disc_offsets = [0]
            else:
                if not (iso_disc_map := self.decrypt_pgd(self.pbp_header.psar_offset + 0x200)):
                    return False
                self.fp.seek(self.pbp_header.psar_offset)
                self.iso_disc_map = PSTitleImgHeader.unpack(self.fp.read(0x200) + iso_disc_map)
                self.num_discs = len(self.iso_disc_map.discs_start_offsets)
                self.disc_offsets = self.iso_disc_map.discs_start_offsets

            self.iso_table_offset = 0x3C00 # Relative to disc offset
            for disc_num, offset in enumerate(self.disc_offsets):
                pgd_offset = 0x400 + offset
                if not (decrypted_table := self.decrypt_pgd(self.pbp_header.psar_offset + pgd_offset)):
                    return False
                decrypted_table = io.BytesIO(decrypted_table)
                num_sectors = self.data_track_sectors(decrypted_table)
                if num_sectors:
                    self.disc_sizes.append(num_sectors * 2352)
                else:
                    decrypted_table.seek(self.iso_table_offset)
                    self.disc_sizes.append(0)
                    entry = PS1TableEntry.unpack(decrypted_table.read(0x20))
                    while entry.block_size:
                        if entry.block_marker == 0:
                            break
                        self.disc_sizes[disc_num] += 0x9300
                        entry = PS1TableEntry.unpack(decrypted_table.read(0x20))

                self.disc_tables.append(decrypted_table)
            self._size = self.size = self.disc_sizes[self.disc_num]
        else:
            self._size = self.size = self.pbp_header.size
            return True

        self.decrypted_buf = InMemoryRolloverTempFile(self.size)
        return True

    @staticmethod
    def extract_frames_from_cue(iso_table, cue_offset, gap):
        iso_table.seek(cue_offset)
        cue_entry = CueEntry.unpack(iso_table.read(CueEntry.struct.size))

        if cue_entry.is_valid_track:
            return cue_entry.get_index1_sectors(gap)

        return -1

    def get_track_size_from_cue(self, iso_table, cue_offset):
        cur_track_offset = self.extract_frames_from_cue(iso_table, cue_offset, 2)
        if cur_track_offset < 0:
            return -1

        next_track_offset = self.extract_frames_from_cue(iso_table, cue_offset + CueEntry.struct.size, 2)
        if next_track_offset < 0:
            # get disc size to calculate last track, no gap after last track
            next_track_offset = self.extract_frames_from_cue(iso_table, 0x414, 0)
            if next_track_offset < 0:
                return -1

        return next_track_offset - cur_track_offset

    def data_track_sectors(self, iso_table):
        cue_offset = 0x41E  # track 01 offset
        track_size = self.get_track_size_from_cue(iso_table, cue_offset) - 2 * 75  # subtract 2 seconds
        if track_size < 0:
            return 0

        return track_size

    @staticmethod
    def aes128_psp_decrypt(key: bytes, iv: bytes, index: int, buffer: bytearray, size: int):
        # Calculate the number of 16-byte blocks needed
        num_blocks = (size + 15) // 16

        # Precompute all counter values
        start_counter = index + 1
        end_counter = index + num_blocks
        counter_vals = np.arange(start_counter, end_counter + 1, dtype='<u4')  # Little-endian

        # Build counter blocks
        iv_first_12 = np.frombuffer(iv[:12], dtype=np.uint8)
        counter_blocks = np.zeros((num_blocks, 16), dtype=np.uint8)
        counter_blocks[:, :12] = iv_first_12  # Broadcast IV's first 12 bytes
        counter_blocks[:, 12:] = counter_vals.view(np.uint8).reshape(-1, 4)  # Little-endian counter values

        # Decrypt all counter blocks in one batch
        cipher = AES.new(key, AES.MODE_ECB)
        counter_bytes = counter_blocks.tobytes()
        decrypted = cipher.decrypt(counter_bytes)
        decrypted_blocks = np.frombuffer(decrypted, dtype=np.uint8).reshape(-1, 16)

        # Initialize previous block
        if index > 0:
            prev_initial = np.zeros(16, dtype=np.uint8)
            prev_initial[:12] = iv_first_12
            prev_initial[12:] = np.frombuffer(struct.pack("<I", index), dtype=np.uint8)
        else:
            prev_initial = np.zeros(16, dtype=np.uint8)

        # Compute keystream using vectorized operations
        keystream = np.empty_like(decrypted_blocks)
        keystream[0] = prev_initial ^ decrypted_blocks[0]
        if num_blocks > 1:
            keystream[1:] = counter_blocks[:-1] ^ decrypted_blocks[1:]

        # Flatten keystream and XOR with the buffer
        buffer_np = np.frombuffer(buffer, dtype=np.uint8, count=size).copy()
        keystream_flat = keystream.ravel()[:size]
        buffer_np ^= keystream_flat

        return buffer_np.tobytes()

    def init_psp_decrypt(self, eboot: int, mac: bytes, header: bytes, offset1: int, offset2: int):
        """Initialize PSP decryption keys"""
        tmp = bytearray(16)

        # Set up key using kirk7_key63
        key_cipher = AES.new(self.kirk7_key63, AES.MODE_ECB)
        tmp_data = key_cipher.decrypt(header[offset1:offset1 + 16])
        tmp[:] = tmp_data

        # Process with kirk7_key38
        aes_cipher = AES.new(self.kirk7_key38, AES.MODE_ECB)
        tmp_data = aes_cipher.decrypt(bytes(tmp))
        tmp[:] = tmp_data

        # Create IV
        iv = bytearray(16)
        for i in range(16):
            iv[i] = mac[i] ^ tmp[i] ^ header[offset2 + i] ^ self.amctl_hashkey_3[i] ^ self.amctl_hashkey_5[i]

        # Process with kirk7_key39
        aes_cipher = AES.new(self.kirk7_key39, AES.MODE_ECB)
        tmp_data = aes_cipher.decrypt(bytes(iv))
        iv[:] = tmp_data

        # Final XOR with amctl_hashkey_4
        for i in range(16):
            iv[i] ^= self.amctl_hashkey_4[i]

        return self.kirk7_key63, bytes(iv)

    def decrypt_block(self, block_num, decrypt_key):
        # Read and decrypt table entry
        (table_info, abs_offset) = self.read_table_entry(block_num)

        self.fp.seek(abs_offset)
        data = bytearray(self.fp.read(table_info.block_size))

        # Additional decryption if needed
        if table_info.block_flags is not None and table_info.block_flags & 4 == 0:
            try:
                data = self.aes128_psp_decrypt(self.psp_key, self.psp_iv, table_info.block_offset // 16, data, table_info.block_size)
            except:
                raise

        # Process the data block
        is_compressed = table_info.block_size != self.iso_block_size

        if is_compressed:
            # Decompress LZRC data
            out_data = decompress_bytes(bytes(data), self.iso_block_size, self.type)
            if out_data is None:
                raise RuntimeError("ERROR: LZRC decompression failed!")
        else:
            out_data = bytes(data)

        return out_data

    def read(self, size=-1):
        if size < 0:
            size = self.size - self._pos

        read_pos = self._pos

        if self._pos >= self.size:
            return b""

        if self._pos + size > self.bytes_written:
            self.decrypted_buf.seek(self.bytes_written)
            bytes_to_read = (self._pos + size) - self.bytes_written

            bytes_read = 0
            while bytes_read < bytes_to_read and self.bytes_written < self.size:
                block_data = self.decrypt_block(self.blocks_read, None)

                if block_data == -1:
                    break

                self.decrypted_buf.write(block_data)
                self.bytes_written += len(block_data)
                bytes_read += len(block_data)
                self.blocks_read += 1

        data = self.decrypted_buf[read_pos:min(self.size, read_pos + size)]
        self._pos = read_pos + len(data)
        return data

    def read_table_entry(self, block_num):
        if self.type == 1:
            table_offset = self.iso_table_offset + block_num * 0x20
            iso_table = self.disc_tables[self.disc_num]

            iso_table.seek(table_offset)
            table = PS1TableEntry.unpack(iso_table.read(0x20))
            return table, self.pbp_header.psar_offset + table.block_offset + self.iso_base_offset + self.disc_offsets[self.disc_num]
        else:
            table_offset = 32 * block_num

            self.iso_table.seek(table_offset)
            table = PSARBlockInfo(struct.unpack("<IIIIIIII", self.iso_table.read(32)))
            return table, self.pbp_header.psar_offset + table.block_offset
