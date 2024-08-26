import hashlib
import struct

from Crypto.Cipher import AES
from Crypto.Hash import SHA1
from Crypto.Util import Counter, strxor
from Crypto.Util.number import long_to_bytes

from post_psx.types import PKGMetaData, PKGHeader, PKGExtHeader, PKGEntry
from utils.files import get_file_size
from xor_cipher import cyclic_xor

import logging

LOGGER = logging.getLogger(__name__)


class DebugCTR:
    def __init__(self, pkg_header_digest, block_num):
        self.key = bytearray(pkg_header_digest[:8] * 2 + pkg_header_digest[8:16] * 2 + bytes(32))
        self.counter = block_num
        self.block = bytes(16)
        self.block_index = 16  # Force initial update

    def update_block(self):
        self.key[56:64] = long_to_bytes(self.counter, 8)
        self.block = hashlib.sha1(self.key).digest()[:16]
        self.block_index = 0
        self.counter += 1

    def crypt(self, data):
        data_len = len(data)
        result = bytearray(data_len)
        i = 0
        while i < data_len:
            if self.block_index == 16:
                self.update_block()
            chunk_size = min(16 - self.block_index, data_len - i)
            result[i:i + chunk_size] = cyclic_xor(
                data[i:i + chunk_size],
                self.block[self.block_index:self.block_index + chunk_size]
            )
            self.block_index += chunk_size
            i += chunk_size
        return bytes(result)

    encrypt = decrypt = crypt


class Pkg:
    PSP_AES_KEY = bytes([0x07, 0xF2, 0xC6, 0x82, 0x90, 0xB5, 0x0D, 0x2C,
                         0x33, 0x81, 0x8D, 0x70, 0x9B, 0x60, 0xE6, 0x2B])

    PS3_AES_KEY = bytes([0x2E, 0x7B, 0x71, 0xD7, 0xC9, 0xC9, 0xA1, 0x4E,
                         0xA3, 0x22, 0x1F, 0x18, 0x88, 0x28, 0xB8, 0xF8])

    PKG_AES_KEY_VITA_1 = bytes([0xE3, 0x1A, 0x70, 0xC9, 0xCE, 0x1D, 0xD7, 0x2B,
                                0xF3, 0xC0, 0x62, 0x29, 0x63, 0xF2, 0xEC, 0xCB])

    PKG_AES_KEY_VITA_2 = bytes([0x42, 0x3A, 0xCA, 0x3A, 0x2B, 0xD5, 0x64, 0x9F,
                                0x96, 0x86, 0xAB, 0xAD, 0x6F, 0xD8, 0x80, 0x1F])

    PKG_AES_KEY_VITA_3 = bytes([0xAF, 0x07, 0xFD, 0x59, 0x65, 0x25, 0x27, 0xBA,
                                0xF1, 0x33, 0x89, 0x66, 0x8B, 0x17, 0xD9, 0xEA])

    PKG_PLATFORM_TYPE_PS3 = 0x0001
    PKG_PLATFORM_TYPE_PSP_PSVITA = 0x0002

    PKG_FILE_ENTRY_PSP = 0x10000000

    PKG_DEBUG_TYPE = 0x0000
    PKG_RETAIL_TYPE = 0x8000

    def __init__(self, fp):
        self.fp = fp
        self.pkg_header = None
        self.pkg_ext_header = None
        self.metadata = PKGMetaData()
        self._entries = {}
        self.pkg_key = None
        self.aes_context = None

    def parse_header(self):
        self.fp.seek(0)
        self.pkg_header = PKGHeader.unpack(self.fp.read(PKGHeader.struct.size))

        LOGGER.debug("Header: pkg_magic = 0x%x = %s",
                     int.from_bytes(self.pkg_header.pkg_magic, byteorder="little"),
                     self.pkg_header.pkg_magic)
        LOGGER.debug("Header: pkg_type = 0x%x = %d", *[self.pkg_header.pkg_type] * 2)
        LOGGER.debug("Header: pkg_platform = 0x%x = %d", *[self.pkg_header.pkg_type] * 2)
        LOGGER.debug("Header: meta_offset = 0x%x = %d", *[self.pkg_header.meta_offset] * 2)
        LOGGER.debug("Header: meta_count = 0x%x = %d", *[self.pkg_header.meta_count] * 2)
        LOGGER.debug("Header: meta_size = 0x%x = %d", *[self.pkg_header.meta_size] * 2)
        LOGGER.debug("Header: file_count = 0x%x = %d", *[self.pkg_header.file_count] * 2)
        LOGGER.debug("Header: pkg_size = 0x%x = %d", *[self.pkg_header.pkg_size] * 2)
        LOGGER.debug("Header: data_offset = 0x%x = %d", *[self.pkg_header.data_offset] * 2)
        LOGGER.debug("Header: data_size = 0x%x = %d", *[self.pkg_header.data_size] * 2)
        LOGGER.debug("Header: title_id = %s", self.pkg_header.title_id)
        LOGGER.debug("Header: qa_digest = 0x%x", int.from_bytes(self.pkg_header.digest, byteorder="little"))

        if not self.pkg_header.check_magic():
            LOGGER.error("Not a PKG file!")
            return False

        if self.pkg_header.pkg_platform == self.PKG_PLATFORM_TYPE_PS3:
            self.pkg_key = self.PS3_AES_KEY
        elif self.pkg_header.pkg_platform == self.PKG_PLATFORM_TYPE_PSP_PSVITA:
            self.pkg_key = self.PSP_AES_KEY
        else:
            LOGGER.error("PKG type not supported")
            return False

        if self.pkg_header.pkg_platform == self.PKG_PLATFORM_TYPE_PSP_PSVITA:
            # Parse extended header for PSP/Vita packages
            self.fp.seek(PKGHeader.struct.size)
            self.pkg_ext_header = PKGExtHeader.unpack(self.fp.read(PKGExtHeader.struct.size))
            if not self.pkg_ext_header.check_magic():
                LOGGER.error("PKG extended header corrupt")
                return False

            LOGGER.debug("Extended header: magic = 0x%x = %s",
                         int.from_bytes(self.pkg_ext_header.magic, byteorder="little"),
                         self.pkg_ext_header.magic)
            LOGGER.debug("Extended header: unknown_1 = 0x%x = %d", *[self.pkg_ext_header.unknown_1] * 2)
            LOGGER.debug("Extended header: ext_hdr_size = 0x%x = %d", *[self.pkg_ext_header.ext_hdr_size] * 2)
            LOGGER.debug("Extended header: ext_data_size = 0x%x = %d", *[self.pkg_ext_header.ext_data_size] * 2)
            LOGGER.debug("Extended header: main_and_self.pkg_ext_headers_hmac_offset = 0x%x = %d",
                         *[self.pkg_ext_header.main_and_ext_headers_hmac_offset] * 2)
            LOGGER.debug("Extended header: metadata_header_hmac_offset = 0x%x = %d",
                         *[self.pkg_ext_header.metadata_header_hmac_offset] * 2)
            LOGGER.debug("Extended header: tail_offset = 0x%x = %d", *[self.pkg_ext_header.tail_offset] * 2)
            LOGGER.debug("Extended header: pkg_key_id = 0x%x = %d", *[self.pkg_ext_header.pkg_key_id] * 2)
            LOGGER.debug("Extended header: full_header_hmac_offset = 0x%x = %d",
                         *[self.pkg_ext_header.full_header_hmac_offset] * 2)

        if self.pkg_header.pkg_type not in [self.PKG_DEBUG_TYPE, self.PKG_RETAIL_TYPE]:
            LOGGER.error(f"Unknown PKG type (0x{self.pkg_header.pkg_type:x})")
            return False

        # TODO: Split packages
        if self.pkg_header.pkg_size > get_file_size(self.fp):
            LOGGER.error("Split package not support")
            return False

        if self.pkg_header.data_size + self.pkg_header.data_offset > self.pkg_header.pkg_size:
            LOGGER.error(f"PKG data size mismatch ("
                         f"data_size=0x{self.pkg_header.data_size:x}, "
                         f"data_offset=0x{self.pkg_header.data_size:x}, "
                         f"file_size=0x{self.pkg_header.data_size:x})")
            return False

        return True

    def parse_metadata(self):
        self.fp.seek(self.pkg_header.meta_offset)
        for i in range(0, self.pkg_header.meta_count):
            metadata_id, entry_size = struct.unpack(">II", self.fp.read(8))
            metadata = self.fp.read(entry_size)
            if metadata_id == 0x1:
                self.metadata.drm_type, = struct.unpack(">I", metadata)
            elif metadata_id == 0x2:
                self.metadata.content_type, = struct.unpack(">I", metadata)
            elif metadata_id == 0x3:
                self.metadata.package_type, = struct.unpack(">I", metadata)
            elif metadata_id == 0x4:
                self.metadata.package_size, = struct.unpack(">Q", metadata)
            elif metadata_id == 0x5:
                self.metadata.package_revision = self.metadata.package_revision.unpack(metadata)
            elif metadata_id == 0x6:
                self.metadata.title_id = metadata
            elif metadata_id == 0x7:
                self.metadata.qa_digest = metadata
            elif metadata_id == 0x8:
                self.metadata.software_revision = self.metadata.software_revision.unpack(metadata)
            elif metadata_id == 0x9:
                self.metadata.unk_0x9, = struct.unpack(">Q", metadata)
            elif metadata_id == 0xA:
                self.metadata.install_dir = metadata
            elif metadata_id == 0xB:
                self.metadata.unk_0xB, = struct.unpack(">Q", metadata)
            elif metadata_id == 0xC:
                continue
            elif metadata_id == 0xD:
                self.metadata.item_info = self.metadata.item_info.unpack(metadata)
            elif metadata_id == 0xE:
                self.metadata.sfo_info = self.metadata.sfo_info.unpack(metadata)
            elif metadata_id == 0xF:
                self.metadata.unknown_data_info = self.metadata.unknown_data_info.unpack(metadata)
            elif metadata_id == 0x10:
                self.metadata.entirety_info = self.metadata.entirety_info.unpack(metadata)
            elif metadata_id == 0x11:
                self.metadata.version_info = self.metadata.version_info.unpack(metadata)
            elif metadata_id == 0x12:
                self.metadata.self_info = self.metadata.self_info.unpack(metadata)
            else:
                LOGGER.error("Unknown metadata type %d", metadata_id)
                continue

        if self.pkg_header.pkg_platform == self.PKG_PLATFORM_TYPE_PSP_PSVITA and 0x15 <= self.metadata.content_type <= 0x17:
            if self.metadata.content_type == 0x15:
                key = self.PKG_AES_KEY_VITA_1
            elif self.metadata.content_type == 0x16:
                key = self.PKG_AES_KEY_VITA_2
            else:
                key = self.PKG_AES_KEY_VITA_3
            cipher = AES.new(key, AES.MODE_ECB)
            self.pkg_key = cipher.encrypt(bytes(self.pkg_header.pkg_data_riv))

    def init_cipher(self, block_num, key):
        if self.pkg_header.pkg_type == self.PKG_RETAIL_TYPE:
            ctr = Counter.new(128, initial_value=(
                    int.from_bytes(self.pkg_header.pkg_data_riv, byteorder='big') + block_num
            ))
            self.aes_context = AES.new(key, AES.MODE_CTR, counter=ctr)
        else:
            # Debug mode
            self.aes_context = DebugCTR(self.pkg_header.digest, block_num)

    def entries(self):
        if len(self._entries) == self.pkg_header.file_count:
            yield from iter(self._entries.values())

        for block in range(0, self.pkg_header.file_count * 2, 2):
            self.init_cipher(block, self.pkg_key)
            self.fp.seek(self.pkg_header.data_offset + (16 * block))
            enc = self.fp.read(32)
            entry_data = self.decrypt(enc)
            entry = PKGEntry.unpack(entry_data)

            name_block_start = entry.name_offset // 16
            self.fp.seek(self.pkg_header.data_offset + (16 * name_block_start))
            if entry.type & self.PKG_FILE_ENTRY_PSP:
                entry.key = self.PSP_AES_KEY
            else:
                entry.key = self.PS3_AES_KEY
            self.init_cipher(name_block_start, entry.key)
            name = self.decrypt(self.fp.read(entry.name_size))
            entry.name_decoded = name.rstrip(b"\x00").decode("utf-8", errors="replace")
            self._entries[entry.name_decoded] = entry
            yield entry

    def decrypt(self, blocks):
        return self.aes_context.encrypt(blocks)
