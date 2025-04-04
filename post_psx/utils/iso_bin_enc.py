from functools import lru_cache

from Crypto.Cipher import AES
from Crypto.Hash import SHA1

from post_psx.types import IsoBinEncMeta
from post_psx.utils.npd import NPDFile


class IsoBinEncFile(NPDFile):
    ps2_key_cex_data = bytes([0x10, 0x17, 0x82, 0x34, 0x63, 0xF4, 0x68, 0xC1,
                              0xAA, 0x41, 0xD7, 0x00, 0xB1, 0x40, 0xF2, 0x57])
    ps2_key_cex_meta = bytes([0x38, 0x9D, 0xCB, 0xA5, 0x20, 0x3C, 0x81, 0x59,
                              0xEC, 0xF9, 0x4C, 0x93, 0x93, 0x16, 0x4C, 0xC9])

    def __init__(self, fp, file_name, edat_key):
        super().__init__(fp, file_name, edat_key)
        self.data_blocks_per_section = 512
        self.data_key = self.meta_key = None
        if edat_key:
            cipher = AES.new(self.ps2_key_cex_data, AES.MODE_CBC, bytearray(16))
            self.data_key = cipher.encrypt(edat_key)
            cipher = AES.new(self.ps2_key_cex_meta, AES.MODE_CBC, bytearray(16))
            self.meta_key = cipher.encrypt(edat_key)

    def test_decrypt(self, decrypt_key):
        return self.decrypt_block(0, decrypt_key) is not None

    def decrypt_block(self, block_num, decrypt_key):
        if not self.data_key:
            cipher = AES.new(self.ps2_key_cex_data, AES.MODE_CBC, bytearray(16))
            self.data_key = cipher.encrypt(decrypt_key)
        if not self.meta_key:
            cipher = AES.new(self.ps2_key_cex_meta, AES.MODE_CBC, bytearray(16))
            self.meta_key = cipher.encrypt(decrypt_key)

        data_position, metadata_position, data_block_section_pos = self._calculate_positions(block_num)

        metadata_decrypted = self.get_metadata_block(metadata_position, self.meta_key)
        metadata = IsoBinEncMeta.unpack(metadata_decrypted[0x20*data_block_section_pos:0x20*data_block_section_pos+0x20])

        if metadata.block_id != block_num:
            return None

        self.fp.seek(data_position)
        block_enc = self.fp.read(self.edat_header.block_size)

        sha1 = SHA1.new(block_enc)
        if metadata.sha1 != sha1.digest():
            return None

        cipher = AES.new(self.data_key, AES.MODE_CBC, bytearray(16))
        decrypted = cipher.decrypt(block_enc)

        return decrypted

    def _calculate_positions(self, block_index):
        section = block_index // self.data_blocks_per_section
        data_block_section_pos = block_index % self.data_blocks_per_section

        data_position = (self.edat_header.block_size +
                         (self.edat_header.block_size +  # Initial metadata block
                         (section * self.edat_header.block_size) +  # Additional metadata blocks
                         ((section * self.data_blocks_per_section) +  # Previous full sections' data blocks
                          data_block_section_pos) * self.edat_header.block_size))  # Position within current section

        metadata_position = self.edat_header.block_size + section * (self.data_blocks_per_section + 1) * self.edat_header.block_size

        return data_position, metadata_position, data_block_section_pos


    @lru_cache
    def get_metadata_block(self, pos, dec_key):
        self.fp.seek(pos)
        metadata_encrypted = self.fp.read(self.edat_header.block_size)
        cipher = AES.new(dec_key, AES.MODE_CBC, bytearray(16))
        return cipher.decrypt(metadata_encrypted)
