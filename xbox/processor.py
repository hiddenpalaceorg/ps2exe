import ctypes
import datetime
import hashlib
import io
import logging
import os
import re
import struct
import subprocess
import sys
from hashlib import sha1

import pefile
from Crypto.Cipher import AES

from common.iso_path_reader.methods.compressed import CompressedPathReader
from common.processor import BaseIsoProcessor
from utils.files import ConcatenatedFile
from xbox.path_reader import XboxPathReader, XboxStfsPathReader
from xbox.stfs.stfs import STFS
from xbox.utils.xdbf import XDBF

LOGGER = logging.getLogger(__name__)

class XboxIsoProcessor(BaseIsoProcessor):
    ignored_paths = [
        re.compile(".*\.xbe$", re.IGNORECASE)
    ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.exe_info = {}

    def get_disc_type(self):
        if isinstance(self.iso_path_reader, CompressedPathReader):
            return {"disc_type": "hdd"}
        return {"disc_type": "dvdr"}

    def get_exe_filename(self):
        found_exes = {}
        for file in self.iso_path_reader.iso_iterator(self.iso_path_reader.get_root_dir(), recursive=True):
            file_path = self.iso_path_reader.get_file_path(file)
            file_path_lower = file_path.lower()
            if (file_path_lower.endswith(".xbe") or
                file_path_lower.endswith(".xex") or
                file_path_lower.endswith(".exe")
            ) and not file_path_lower.endswith("dashupdate.xbe") and not '$systemupdate/' in file_path_lower:
                try:
                    if not (exe_info := self._parse_exe(file_path)):
                        continue
                except (pefile.PEFormatError, AssertionError, struct.error):
                        continue
                self.ignored_paths.append(re.compile(rf"^{re.escape(file_path_lower)}$", re.IGNORECASE))
                if exe_info.get("header_title") in ["CDX", "Installer"]:
                    LOGGER.info("Found installer or CDX xbe, ignoring and finding another XBE")
                    continue
                LOGGER.info("exe date: %s", exe_info["exe_date"])
                found_exes[file_path] = exe_info

        if not found_exes:
            return

        exe = max(found_exes.items(), key=lambda x: x[1]["exe_date"])[0]
        LOGGER.info("Found latest exe: %s", exe)
        self.exe_info = found_exes[exe]
        return exe

    def get_most_recent_file_info(self, exe_date):
        if not isinstance(self.iso_path_reader, XboxPathReader):
            return super().get_most_recent_file_info(exe_date)
        return {}

    def _parse_exe(self, exe_filename):
        LOGGER.info("Parsing xbe file headers. xbe name: %s", exe_filename)
        try:
            result = {}
            with self.iso_path_reader.open_file(self.iso_path_reader.get_file(exe_filename)) as f:
                f.seek(0x104)
                base_addr, exe_time, cert_addr = struct.unpack("<I12xII", f.read(24))
                result["exe_date"] = datetime.datetime.fromtimestamp(exe_time, tz=datetime.timezone.utc)
                if (cert_addr > base_addr):
                    f.seek(cert_addr - base_addr)
                    cert_timestamp, cert_game_id, b, a, cert_title = struct.unpack("<4xIHss40s", f.read(52))
                    result["header_release_date"] = datetime.datetime.fromtimestamp(
                        cert_timestamp,
                        tz=datetime.timezone.utc)
                    maker_id = ""
                    for char in [a, b]:
                        try:
                            if char[0] > 0x20:
                                maker_id += char.decode()
                            else:
                                maker_id += "\\x" + ('%02X' % char[0])
                        except UnicodeDecodeError:
                            maker_id += "\\x" + ('%02X' % char[0])

                    result["header_title"] = cert_title.decode("UTF-16le").strip().replace("\x00", "")
                    result["header_maker_id"] = maker_id
                    result["header_product_number"] = "%03d" % cert_game_id

                    f.seek(108, os.SEEK_CUR)
                    cert_regions, = struct.unpack("<I", f.read(4))
                    result["exe_signing_type"] = "debug" if cert_regions & 0x80000000 else "retail"

                    xbe_hash = hashlib.md5()
                    f.seek(base_addr)
                    xbe_hash.update(f.read())
                    result["alt_md5"] = xbe_hash.hexdigest()

            return result
        except FileNotFoundError:
            return False

    def get_extra_fields(self):
        return self.exe_info


char_t = ctypes.c_char
uint8_t  = ctypes.c_byte
uint16_t = ctypes.c_ushort
uint32_t = ctypes.c_uint


# ImageXEXHeader for "XEX0" format, which only contains very basic information (>=1332)
class ImageXEXHeader_30(ctypes.BigEndianStructure):
    _fields_ = [
        ("Magic", uint32_t),
        ("SizeOfHeaders", uint32_t),
        ("LoadAddress", uint32_t),
        ("Unknown14", uint32_t),
        ("HeaderDirectoryEntryCount", uint32_t),
    ]


# ImageXEXHeader for "XEX?" format, which doesn't contain a SecurityInfo struct (>=1529)
class ImageXEXHeader_3F(ctypes.BigEndianStructure):
    _fields_ = [
        ("Magic", uint32_t),
        ("ModuleFlags", uint32_t),
        ("SizeOfHeaders", uint32_t),
        ("SizeOfDiscardableHeaders", uint32_t),
        ("LoadAddress", uint32_t),
        ("Unknown14", uint32_t),
        ("HeaderDirectoryEntryCount", uint32_t),
    ]


class ImageXEXHeader(ctypes.BigEndianStructure):
    _fields_ = [
        ("Magic", uint32_t),
        ("ModuleFlags", uint32_t),
        ("SizeOfHeaders", uint32_t),
        ("SizeOfDiscardableHeaders", uint32_t),
        ("SecurityInfo", uint32_t),
        ("HeaderDirectoryEntryCount", uint32_t),
    ]


class XEX2HVImageInfo(ctypes.BigEndianStructure):
    _fields_ = [
        ("Signature", uint8_t * 0x100),
        ("InfoSize", uint32_t),
        ("ImageFlags", uint32_t),
        ("LoadAddress", uint32_t),
        ("ImageHash", uint8_t * 0x14),
        ("ImportTableCount", uint32_t),
        ("ImportDigest", uint8_t * 0x14),
        ("MediaID", uint8_t * 0x10),
        ("ImageKey", uint8_t * 0x10),
        ("ExportTableAddress", uint32_t),
        ("HeaderHash", uint8_t * 0x14),
        ("GameRegion", uint32_t),
    ]


class XEX2SecurityInfo(ctypes.BigEndianStructure):
    _fields_ = [
        ("Size", uint32_t),
        ("ImageSize", uint32_t),
        ("ImageInfo", XEX2HVImageInfo),
        ("AllowedMediaTypes", uint32_t),
        ("PageDescriptorCount", uint32_t),
    ]


class XEX1HVImageInfo(ctypes.BigEndianStructure):
    _fields_ = [
        ("Signature", uint8_t * 0x100),
        ("ImageHash", uint8_t * 0x14),
        ("ImportDigest", uint8_t * 0x14),
        ("LoadAddress", uint32_t),
        ("ImageKey", uint8_t * 0x10),
        ("MediaID", uint8_t * 0x10),
        ("GameRegion", uint32_t),
        ("ImageFlags", uint32_t),
        ("ExportTableAddress", uint32_t),
    ]


class XEX1SecurityInfo(ctypes.BigEndianStructure):
    _fields_ = [
        ("Size", uint32_t),
        ("ImageSize", uint32_t),
        ("ImageInfo", XEX1HVImageInfo),
        ("AllowedMediaTypes", uint32_t),
        ("PageDescriptorCount", uint32_t),
    ]


class XEX25HVImageInfo(ctypes.BigEndianStructure):
    _fields_ = [
        ("Signature", uint8_t * 0x100),
        ("ImageHash", uint8_t * 0x14),
        ("ImportDigest", uint8_t * 0x14),
        ("LoadAddress", uint32_t),
        ("ImageKey", uint8_t * 0x10),
        ("ImageFlags", uint32_t),
        ("ExportTableAddress", uint32_t),
    ]


class XEX25SecurityInfo(ctypes.BigEndianStructure):
    _fields_ = [
        ("Size", uint32_t),
        ("ImageSize", uint32_t),
        ("ImageInfo", XEX25HVImageInfo),
        ("AllowedMediaTypes", uint32_t),
        ("PageDescriptorCount", uint32_t),
    ]


class XEX2DHVImageInfo(ctypes.BigEndianStructure):
    _fields_ = [
        ("Signature", uint8_t * 0x100),
        ("ImageHash", uint8_t * 0x14),
        ("ImportDigest", uint8_t * 0x14),
        ("LoadAddress", uint32_t),
        ("ImageFlags", uint32_t),
        ("ExportTableAddress", uint32_t),
        ("Unknown", uint32_t),
    ]


class XEX2DSecurityInfo(ctypes.BigEndianStructure):
    _fields_ = [
        ("Size", uint32_t),
        ("ImageInfo", XEX2DHVImageInfo),
        ("AllowedMediaTypes", uint32_t),
        ("PageDescriptorCount", uint32_t),
    ]


class XEXFileDataDescriptor(ctypes.BigEndianStructure):
    _fields_ = [
        ("Size", uint32_t),  # (Size - 8) / sizeof(XEXRawBaseFileBlock or XEXDataDescriptor) = num blocks
        ("Flags", uint16_t),  # enum: EncryptionType   (0: decrypted / 1: encrypted)
        ("Format", uint16_t),  # enum: CompressionType (0: none / 1: raw / 2: compressed / 3: delta-compressed)
    ]


# After XEXFileDataDescriptor when Format == 1 (aka "uncompressed")
class XEXRawBaseFileBlock(ctypes.BigEndianStructure):
    _fields_ = [
        ("Size", uint32_t),
        ("ZeroSize", uint32_t),  # num zeroes to insert after this block
    ]


# After XEXFileDataDescriptor when Format == 2 (aka compressed)
# (first block has WindowSize prepended to it!)
class XEXCompressedBaseFileBlock(ctypes.BigEndianStructure):
    _fields_ = [
        ("Size", uint32_t),
        ("DataDigest", uint8_t * 0x14),
    ]


# Optional XEX Headers
class Version(ctypes.BigEndianStructure):
    _pack_ = 1
    _fields_ = [
        ("Major", uint8_t, 4),
        ("Minor", uint8_t, 4),
        ("Build", uint16_t, 16),
        ("QFE", uint8_t, 8),
    ]


class XEX2ExecutionID(ctypes.BigEndianStructure):
    _fields_ = [
        ("MediaId", uint32_t),
        ("Version", Version),
        ("BaseVersion", Version),
        ("TitleId", uint32_t),
        ("Platform", uint8_t),
        ("ExecutableType", uint8_t),
        ("DiscNum", uint8_t),
        ("DiscsInSet", uint8_t),
        ("SaveGameId", uint32_t),
    ]


class XEX2VitalStats(ctypes.BigEndianStructure):
    _fields_ = [
        ("Checksum", uint32_t),
        ("Timestamp", uint32_t),
    ]


class ImageXEXDirectoryEntry(ctypes.BigEndianStructure):
    _fields_ = [
        ("Key", uint32_t),
        ("Value", uint32_t),
    ]


class XEX2ResourceInfo(ctypes.BigEndianStructure):
    _fields_ = [
        ("Size", uint32_t),
        ("ResourceId", char_t * 8),
        ("ValueAddress", uint32_t),
        ("ResourceSize", uint32_t),
    ]


class Xbox360IsoProcessor(XboxIsoProcessor):
    ignored_paths = [
        re.compile(".*\$SystemUpdate\/.*", re.IGNORECASE),
        re.compile(".*nxeart$", re.IGNORECASE),
        re.compile(".*AvatarAssetPack$", re.IGNORECASE),
        re.compile(".*\.xex$", re.IGNORECASE),
        re.compile(".*readme.html$", re.IGNORECASE),
        re.compile(".*AvatarAssetPack$", re.IGNORECASE),
        re.compile(".*AvatarAwards$", re.IGNORECASE),
    ]

    XEX2_HEADER_RESOURCE_INFO = 0x2FF
    XEX_FILE_DATA_DESCRIPTOR_HEADER = 0x3FF
    XEX_HEADER_EXECUTION_ID = 0x40006
    XEX_HEADER_VITAL_STATS = 0x00018002
    XEX_ORIGINAL_PE_NAME = 0x183FF

    retail_key = b'\x20\xB1\x85\xA5\x9D\x28\xFD\xC3\x40\x58\x3F\xBB\x08\x96\xBF\x91'
    devkit_key = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    unused_key = b'\xA2\x6C\x10\xF7\x1F\xD9\x35\xE9\x8B\x99\x92\x2C\xE9\x32\x15\x72'

    xex_keys = [retail_key, devkit_key, unused_key]
    xex_key_names = ["retail", "devkit", "xex1"]

    _MAGIC_XEX32 = b"XEX2"  # >=1888
    _MAGIC_XEX31 = b"XEX1"  # >=1838
    _MAGIC_XEX25 = b"XEX%"  # >=1746
    _MAGIC_XEX2D = b"XEX-"  # >=1640
    _MAGIC_XEX3F = b"XEX?"  # >=1529
    _MAGIC_XEX30 = b"XEX0"  # >=1332

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.xex_header = None
        self.xex_magic = None
        self.optional_headers = {}
        self.optional_header_locations = {}
        self.xex_security_info = None

    def get_disc_type(self):
        if isinstance(self.iso_path_reader.fp, ConcatenatedFile):
            return {"disc_type": "xbla"}
        return super().get_disc_type()

    def read_struct(self, f, struct):
        s = struct()
        slen = ctypes.sizeof(s)
        bytes = f.read(slen)
        fit = min(len(bytes), slen)
        ctypes.memmove(ctypes.addressof(s), bytes, fit)
        return s

    def read_dwordBE(self, f):
        s = f.read(4)
        if len(s) < 4:
            return 0
        return struct.unpack('>I', s)[0]

    def parse_xex_header(self, f):
        self.xex_header = None
        self.xex_magic = None
        self.optional_headers = {}
        self.optional_header_locations = {}
        self.xex_security_info = None

        # Read XEX header & directory entry headers
        f.seek(0)
        xex_magic = f.read(4)
        f.seek(0)
        if xex_magic == self._MAGIC_XEX3F:
            self.xex_header = self.read_struct(f, ImageXEXHeader_3F)
        elif xex_magic == self._MAGIC_XEX30:
            self.xex_header = self.read_struct(f, ImageXEXHeader_30)
        elif xex_magic in [self._MAGIC_XEX2D, self._MAGIC_XEX25, self._MAGIC_XEX31, self._MAGIC_XEX32]:
            self.xex_header = self.read_struct(f, ImageXEXHeader)
        else:
            LOGGER.warning("Invalid xex file: bad magic.")
            raise AssertionError("Invalid xex file: bad magic.")

        self.optional_header_locations = {}
        if self.xex_header.HeaderDirectoryEntryCount != 0xFFFFFFFF:
            for i in range(0, self.xex_header.HeaderDirectoryEntryCount):
                dir_header = self.read_struct(f, ImageXEXDirectoryEntry)
                self.optional_header_locations[dir_header.Key] = dir_header.Value

        if xex_magic != self._MAGIC_XEX3F:
            f.seek(self.xex_header.SecurityInfo)
            if xex_magic == self._MAGIC_XEX32:
                self.xex_security_info = self.read_struct(f, XEX2SecurityInfo)
            elif xex_magic == self._MAGIC_XEX31:
                self.xex_security_info = self.read_struct(f, XEX1SecurityInfo)
            elif xex_magic == self._MAGIC_XEX25:
                self.xex_security_info = self.read_struct(f, XEX25SecurityInfo)
            elif xex_magic == self._MAGIC_XEX2D:
                self.xex_security_info = self.read_struct(f, XEX2DSecurityInfo)

        for key in self.optional_header_locations:
            header_value = self.optional_header_locations[key]
            entry_size = key & 0xFF
            if entry_size <= 1:
                # value is stored in the header itself
                self.optional_headers[key] = header_value
                continue

            f.seek(header_value)
            # value is pointer to a structure...
            if key == self.XEX2_HEADER_RESOURCE_INFO:
                self.optional_headers[key] = self.read_struct(f, XEX2ResourceInfo)
            elif key == self.XEX_FILE_DATA_DESCRIPTOR_HEADER:
                self.optional_headers[key] = self.read_struct(f, XEXFileDataDescriptor)
            elif key == self.XEX_HEADER_VITAL_STATS:
                self.optional_headers[key] = self.read_struct(f, XEX2VitalStats)
            elif key == self.XEX_HEADER_EXECUTION_ID:
                self.optional_headers[key] = self.read_struct(f, XEX2ExecutionID)
            elif key == self.XEX_ORIGINAL_PE_NAME:
                size = self.read_dwordBE(f)
                self.optional_headers[key] = f.read(size - 4)

    def get_pe(self, f, decryption_key):
        aes = None
        if decryption_key:
            aes = AES.new(decryption_key, AES.MODE_CBC, b'\0' * 16)

        compression_flag = self.optional_headers[self.XEX_FILE_DATA_DESCRIPTOR_HEADER].Format

        # No compression
        if compression_flag == 0:
            LOGGER.info("xex is uncompressed")
            f.seek(self.xex_header.SizeOfHeaders)
            return io.BytesIO(f.read(self.xex_security_info.ImageSize))
        # Simple Compression
        elif compression_flag == 1:
            LOGGER.debug("xex uses simple compression")
            data_descriptor = self.optional_headers[self.XEX_FILE_DATA_DESCRIPTOR_HEADER]

            f.seek(self.optional_header_locations[self.XEX_FILE_DATA_DESCRIPTOR_HEADER] + 8)
            num_blocks = (data_descriptor.Size - 8) // 8
            # Read block descriptor structs
            xex_blocks = []
            for i in range(0, num_blocks):
                block = self.read_struct(f, XEXRawBaseFileBlock)
                xex_blocks.append(block)

            # Read in basefile
            pe_data = io.BytesIO()

            f.seek(self.xex_header.SizeOfHeaders)
            for block in xex_blocks:
                data_size = block.Size
                zero_size = block.ZeroSize

                data = f.read(data_size)
                if aes:
                    data = aes.decrypt(data)
                pe_data.write(data)
                pe_data.write(b'\0' * zero_size)
            pe_data.seek(0)
            # Invalid PE header, try a different encryption key
            if pe_data.read(2) == b'MZ':
                pe_data.seek(0)
                return pe_data
            return None
        # LZX Compressed
        elif compression_flag == 2:
            LOGGER.debug("xex uses LZX compression")
            f.seek(self.optional_header_locations[self.XEX_FILE_DATA_DESCRIPTOR_HEADER] + 8)
            window_size = self.read_dwordBE(f)
            temp = window_size
            window_bits = 0
            for _ in range(32):
                temp <<= 1
                if temp == 0x80000000:
                    break
                window_bits += 1

            first_block = self.read_struct(f, XEXCompressedBaseFileBlock)
            f.seek(self.xex_header.SizeOfHeaders)
            # Based on: https://github.com/xenia-project/xenia/blob/5f764fc752c82674981a9f402f1bbd96b399112a/src/xenia/cpu/xex_module.cc
            block_header = first_block
            compressed_data = io.BytesIO()
            while block_header.Size != 0:
                # Read the next block header and current block contents.
                data = f.read(block_header.Size)
                if decryption_key:
                    data = aes.decrypt(data)

                # Verify current block
                hash = sha1(data)
                if hash.digest() != bytes(block_header.DataDigest):
                    LOGGER.warning("Could not decrypt xex")
                    return None

                temp_stream = io.BytesIO(data)
                next_block_header = self.read_struct(
                    temp_stream,
                    XEXCompressedBaseFileBlock
                )

                # Does the next block size make sense?
                if next_block_header.Size > 65536:
                    # Block size is invalid.
                    LOGGER.warning("Invalid block size")
                    return {}

                # Read the current block.
                block_size = block_header.Size
                if block_size <= ctypes.sizeof(next_block_header):
                    # Block is missing the "next block" header...
                    LOGGER.warning("Could not find next block")
                    return {}

                block_size -= ctypes.sizeof(next_block_header)

                while block_size > 2:
                    # Get the chunk size.
                    chunk_size = struct.unpack('>H', temp_stream.read(2))[0]
                    block_size -= 2
                    if chunk_size == 0 or chunk_size > block_size:
                        # End of block, or not enough data is available.
                        break

                    p_dblk = temp_stream.read(chunk_size)
                    if len(p_dblk) != chunk_size:
                        LOGGER.warning("Could not read chunk")
                        return None

                    compressed_data.write(p_dblk)
                    block_size -= chunk_size

                # Next block.
                block_header = next_block_header
            compressed_data.seek(0)

            decompressed_size = self.xex_security_info.ImageSize

            lxzd_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "lzxd")
            if os.name == "nt":
                if sys.maxsize > 2 ** 32:
                    lxzd_path = os.path.join(lxzd_path, "win64", "lzxd.exe")
                else:
                    lxzd_path = os.path.join(lxzd_path, "win64", "lzxd.exe")
            elif sys.platform == "linux":
                lxzd_path = os.path.join(lxzd_path, "linux", "lzxd")
            elif sys.platform.startswith("freebsd"):
                lxzd_path = os.path.join(lxzd_path, "freebsd", "lzxd")

            LOGGER.debug("Decompressing xex using lzxd")
            p = subprocess.Popen([lxzd_path, str(decompressed_size), "-", "-"], stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE)
            xex_pe, output_err = p.communicate(compressed_data.getvalue())

            return io.BytesIO(xex_pe)

    def _parse_exe(self, exe_filename):
        if exe_filename.lower().endswith("xbe"):
            return super()._parse_exe(exe_filename)
        LOGGER.info("Parsing xex file headers. xex name: %s", exe_filename)
        result = {}
        with self.iso_path_reader.open_file(self.iso_path_reader.get_file(exe_filename)) as f:
            f.seek(0)
            self.parse_xex_header(f)

            if self.XEX_FILE_DATA_DESCRIPTOR_HEADER not in self.optional_headers:
                return result
            data_descriptor = self.optional_headers[self.XEX_FILE_DATA_DESCRIPTOR_HEADER]

            if self.XEX_HEADER_VITAL_STATS in self.optional_headers:
                result["exe_date"] = datetime.datetime.fromtimestamp(
                    self.optional_headers[self.XEX_HEADER_VITAL_STATS].Timestamp,
                    tz=datetime.timezone.utc
                )

            if self.XEX_ORIGINAL_PE_NAME in self.optional_headers:
                exe_name = self.optional_headers[self.XEX_ORIGINAL_PE_NAME].strip(b"\x00")
                result["alt_exe_filename"] = exe_name.decode("cp1252", errors="ignore")

            if self.xex_security_info:
                if self.xex_magic != self._MAGIC_XEX2D:
                    image_key = self.xex_security_info.ImageInfo.ImageKey

                base_address = self.xex_security_info.ImageInfo.LoadAddress
            else:
                base_address = self.xex_header.LoadAddress

            enc_flag = data_descriptor.Flags

            pe = None
            if enc_flag:
                LOGGER.info("Decrypting xex")
            for i, key in enumerate(self.xex_keys):
                session_key = None
                if enc_flag:
                    aes = AES.new(key, AES.MODE_ECB)
                    session_key = aes.decrypt(bytearray(image_key))
                if pe := self.get_pe(f, session_key):
                    if enc_flag:
                        LOGGER.info("Decrypted using key %s", self.xex_key_names[i])
                        result["exe_signing_type"] = self.xex_key_names[i]
                    break
            if not pe:
                return result

            LOGGER.info("Parsing PE file")
            pe.seek(0)
            pe_headers = pefile.PE(name=None, data=pe.read(), fast_load=True)
            result["alt_exe_date"] = datetime.datetime.fromtimestamp(
                pe_headers.FILE_HEADER.TimeDateStamp,
                tz=datetime.timezone.utc
            )

            pe.seek(0)
            md5 = hashlib.md5(pe.read())
            result["alt_md5"] = md5.hexdigest()

            if self.XEX_HEADER_EXECUTION_ID not in self.optional_headers or \
                    self.XEX2_HEADER_RESOURCE_INFO not in self.optional_headers:
                return result

            execution_id = self.optional_headers[self.XEX_HEADER_EXECUTION_ID]
            resource_info = self.optional_headers[self.XEX2_HEADER_RESOURCE_INFO]

            title_id = f"{execution_id.TitleId:8X}"
            header_resource_id = resource_info.ResourceId.decode()
            if title_id != header_resource_id:
                return result

            title_bytes = execution_id.TitleId.to_bytes(4, byteorder='big')
            result["header_maker_id"] = ""
            for char in range(2):
                try:
                    if title_bytes[char] > 0x20:
                        result["header_maker_id"] += title_bytes[char:char + 1].decode()
                    else:
                        result["header_maker_id"] += "\\x" + ('%02X' % title_bytes[char])
                except UnicodeDecodeError:
                    result["header_maker_id"] += "\\x" + ('%02X' % title_bytes[char])
            result["header_product_number"] = "%03d" % int.from_bytes(title_bytes[2:], byteorder="big")

            LOGGER.info("Parsing XDBF resources")
            xdbf_addr = resource_info.ValueAddress - base_address
            pe.seek(xdbf_addr)
            xdbf_data = io.BytesIO(pe.read(resource_info.ResourceSize))
            if len(xdbf_data.read(1)) != 1:
                return result
            xdbf_data.seek(0)
            try:
                xdbf = XDBF(xdbf_data)
            except AssertionError:
                LOGGER.info("XDBF resources not found or invalid")
                return result
            try:
                result["header_title"] = xdbf.string_table[1].strings[32768].decode()
            except (IndexError, KeyError):
                try:
                    result["header_title"] = xdbf.string_table[xdbf.default_language].strings[32768].decode()
                except (IndexError, KeyError):
                    result["header_title"] = None

        return result


class XboxLiveProcessor(Xbox360IsoProcessor):
    def __init__(self, iso_path_reader, *args, **kwargs):
        if isinstance(iso_path_reader, XboxStfsPathReader):
            super().__init__(iso_path_reader, *args, **kwargs)
            return
        hex_pattern = re.compile(r'.*/?(?:([0-9a-fA-F]{16})|([0-9a-fA-F]{6}~1$))')
        for file in iso_path_reader.iso_iterator(iso_path_reader.get_root_dir(), recursive=True):
            file_path = iso_path_reader.get_file_path(file)
            if hex_pattern.match(file_path):
                f = iso_path_reader.open_file(file)
                f.__enter__()
                if f.read(4) in [b"LIVE", b"PIRS"]:
                    f.seek(0)
                    stfs = STFS(filename=None, fd=f)
                    if stfs.content_type not in [0xD0000, 0x80000]:
                        continue
                    stfs.parse_filetable()
                    iso_path_reader = XboxStfsPathReader(stfs, iso_path_reader.fp)
                    break
        super().__init__(iso_path_reader, *args, **kwargs)

    def get_exe_filename(self):
        # Check for an XNA game EXE
        try:
            gameinfo = self.iso_path_reader.get_file('/GameInfo.bin')
            with self.iso_path_reader.open_file(gameinfo) as info:
                header_struct = ">4sI"
                xna_exe_path = None
                while header_bytes := info.read(struct.calcsize(header_struct)):
                    magic, size = struct.unpack(header_struct, header_bytes)
                    if magic == b'EXEC':
                        virtual_titleid, module_name, build_description = struct.unpack(">32sx42sx64sx", info.read(size))
                        module_name = module_name.rstrip(b"\x00").decode()
                        xna_exe_path = f'/584E07D1/{module_name}'
                    elif magic == b'COMM':
                        title_id,  = struct.unpack(">I", info.read(size))
                        self.exe_info["header_product_number"] = title_id
                    elif magic == b'TITL':
                        title, description, unk = struct.unpack(">256s512s512s", info.read(size))
                        self.exe_info['header_title'] = title.decode("UTF-16be").strip().replace("\x00", "")
                    else:
                        self.exe_info = {}
                        return super().get_exe_filename()

                if xna_exe_path:
                    xna_exe = self.iso_path_reader.get_file(xna_exe_path)
                    with self.iso_path_reader.open_file(xna_exe):
                        self.ignored_paths += [re.compile(f'^{re.escape(xna_exe_path)}$', re.IGNORECASE)]
                        return xna_exe_path
        except FileNotFoundError:
            return super().get_exe_filename()

        return super().get_exe_filename()

    def get_disc_type(self):
        return {"disc_type": "xbla"}

    def get_extra_fields(self):
        return {**super().get_extra_fields(), **{"system": "xbox360"}}
