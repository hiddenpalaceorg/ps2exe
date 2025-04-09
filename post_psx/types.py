import dataclasses
import struct

from dataclasses import dataclass, field
from typing import List, Tuple, Optional


class StructMeta(type):
    def __init__(cls, name, bases, d):
        if dataclasses.is_dataclass(d):
            raise ValueError("Class {} is not a dataclass".format(name))
        if 'struct' not in d:
            raise ValueError("Class {} doesn't define struct".format(name))
        type.__init__(cls, name, bases, d)


class Struct:
    __metaclass__ = StructMeta
    struct = None
    size = 0

    def pack(self):
        return self.struct.pack(*dataclasses.astuple(self))

    @classmethod
    def unpack(cls, data):
        return cls(*cls.struct.unpack(data))


@dataclass
class PKGHeader(Struct):
    pkg_magic: bytes  # Magic (0x7f504b47) (" PKG")
    pkg_type: int  # Release type (Retail:0x8000, Debug:0x0000)
    pkg_platform: int  # Platform type (PS3:0x0001, PSP:0x0002)
    meta_offset: int  # Metadata offset. Usually 0xC0 for PS3, usually 0x280 for PSP and PSVita
    meta_count: int  # Metadata item count
    meta_size: int  # Metadata size.
    file_count: int  # Number of files
    pkg_size: int  # PKG size in bytes
    data_offset: int  # Encrypted data offset
    data_size: int  # Encrypted data size in bytes
    title_id: bytes = field(default_factory=lambda: b'\x00' * 0x24)  # Title ID
    digest: bytearray = field(default_factory=lambda: bytearray(0x10))  # hash of "files + attribs"
    pkg_data_riv: bytearray = field(default_factory=lambda: bytearray(0x10))
    pkg_header_digest: bytearray = field(default_factory=lambda: bytearray(0x40))

    struct = struct.Struct(">4sHHIIIIQQQ36s12x16s16s64s")

    def check_magic(self):
        return self.pkg_magic == b"\x7FPKG"


@dataclass
class PKGExtHeader(Struct):
    magic: bytes  # 0x7F657874 (" ext")
    unknown_1: int  # Maybe version. always 1
    ext_hdr_size: int  # Extended header size. ex: 0x40
    ext_data_size: int  # ex: 0x180
    main_and_ext_headers_hmac_offset: int  # ex: 0x100
    metadata_header_hmac_offset: int  # ex: 0x360, 0x390, 0x490
    tail_offset: int  # tail size seams to be always 0x1A0
    padding1: int  # Padding
    pkg_key_id: int  # ID of the AES key used for decryption. PSP = 0x1, PSVita = 0xC0000002, PSM = 0xC0000004
    full_header_hmac_offset: int  # ex: none (old pkg): 0, 0x930
    padding2: bytes = field(default_factory=lambda: b'\x00' * 20)

    struct = struct.Struct(">4sIIIIIQIII20s")

    def check_magic(self):
        return self.magic == b"\x7Fext"


class PKGDirectory:
    def __init__(self, entry):
        self.entry = entry
        self.entries = []
        self.directories = {}

    def entries(self):
        yield from self.entries


@dataclass
class PKGEntry(Struct):
    name_offset: int  # File name offset
    name_size: int  # File name size
    file_offset: int  # File offset
    file_size: int  # File size
    type: int  # File type
    pad: int  # Padding (zeros)
    name_decoded: str = ""
    key: bytes = b""
    directory: PKGDirectory = None

    struct = struct.Struct(">IIQQII")

    @property
    def is_dir(self):
        return self.type & 0xFF == 0x04 and not self.file_size


def to_hex_string(buf: bytes, dotpos: int = None) -> str:
    hex_str = ''.join(f'{b:02x}' for b in buf)
    if dotpos is not None and len(hex_str) > dotpos:
        hex_str = hex_str[:dotpos] + '.' + hex_str[dotpos:]
    return hex_str


@dataclass
class PackageRevision(Struct):
    make_package_npdrm_ver: bytes = field(default_factory=lambda: b'\x00' * 2)
    version: bytes = field(default_factory=lambda: b'\x00' * 2)

    struct = struct.Struct(">HH")


@dataclass
class SoftwareRevision(Struct):
    unk: bytes = field(default_factory=lambda: b'\x00')
    firmware_version: bytes = field(default_factory=lambda: b'\x00' * 3)
    version: bytes = field(default_factory=lambda: b'\x00' * 2)
    app_version: bytes = field(default_factory=lambda: b'\x00' * 2)

    struct = struct.Struct(">s3s2s2s")


@dataclass
class VitaItemInfo(Struct):
    offset: int = 0
    size: int = 0
    sha256: bytes = field(default_factory=lambda: b'\x00' * 32)

    struct = struct.Struct(">II32s")


@dataclass
class VitaSfoInfo(Struct):
    param_offset: int = 0
    param_size: int = 0
    unk_1: int = 0
    psp2_system_ver: int = 0
    unk_2: bytes = field(default_factory=lambda: b'\x00' * 8)
    param_digest: bytes = field(default_factory=lambda: b'\x00' * 32)

    struct = struct.Struct(">IIII8s32s")


@dataclass
class VitaUnknownDataInfo(Struct):
    unknown_data_offset: int = 0
    unknown_data_size: int = 0
    unk: bytes = field(default_factory=lambda: b'\x00' * 32)
    unknown_data_sha256: bytes = field(default_factory=lambda: b'\x00' * 32)

    struct = struct.Struct(">IH32s32s2x")


@dataclass
class VitaEntiretyInfo(Struct):
    entirety_data_offset: int = 0
    entirety_data_size: int = 0
    flags: int = 0
    unk_1: int = 0
    unk_2: int = 0
    unk_3: bytes = field(default_factory=lambda: b'\x00' * 8)
    entirety_digest: bytes = field(default_factory=lambda: b'\x00' * 32)

    struct = struct.Struct(">IIHHI8s32s")


@dataclass
class VitaVersionInfo(Struct):
    publishing_tools_version: int = 0
    psf_builder_version: int = 0
    padding: bytes = field(default_factory=lambda: b'\x00' * 32)

    struct = struct.Struct(">II32s")


@dataclass
class VitaSelfInfo(Struct):
    self_info_offset: int = 0
    self_info_size: int = 0
    unk: bytes = field(default_factory=lambda: b'\x00' * 16)
    self_sha256: bytes = field(default_factory=lambda: b'\x00' * 32)

    struct = struct.Struct(">II16s32s")


@dataclass
class PKGMetaData:
    drm_type: int = 0
    content_type: int = 0
    package_type: int = 0
    package_size: int = 0
    qa_digest: bytes = field(default_factory=lambda: b'\x00' * 24)
    unk_0x9: int = 0
    unk_0xB: int = 0
    package_revision: PackageRevision = field(default_factory=PackageRevision)
    software_revision: SoftwareRevision = field(default_factory=SoftwareRevision)
    title_id: bytes = b""
    install_dir: bytes = b""
    item_info: VitaItemInfo = field(default_factory=VitaItemInfo)
    sfo_info: VitaSfoInfo = field(default_factory=VitaSfoInfo)
    unknown_data_info: VitaUnknownDataInfo = field(default_factory=VitaUnknownDataInfo)
    entirety_info: VitaEntiretyInfo = field(default_factory=VitaEntiretyInfo)
    version_info: VitaVersionInfo = field(default_factory=VitaVersionInfo)
    self_info: VitaSelfInfo = field(default_factory=VitaSelfInfo)


@dataclass
class PBPHeader(Struct):
    magic: bytes
    version: int
    param_sfo_offset: int
    icon0_png_offset: int
    icon1_pmf_offset: int
    pic0_png_offset: int
    pic1_png_offset: int
    snd0_at3_offset: int
    psp_data_offset: int
    psar_offset: int

    struct = struct.Struct("<4sIIIIIIIII")

    def check_magic(self):
        return self.magic == b'\x00PBP'


@dataclass
class NPUMDImg(Struct):
    magic: bytes = 0
    unk1: int = 0
    iso_block_size: int = 0
    content_id: bytes = field(default_factory=lambda: b'\x00' * 36)
    common1: bytes = field(default_factory=lambda: b'\x00' * 4)
    unk2: int = 0
    lba_start: int = 0
    unk3: int = 0
    lba_end: int = 0
    unk4: int = 0
    np_table_offset: int = 0
    game_id: bytes = field(default_factory=lambda: b'\x00' * 10)
    common2: bytes = field(default_factory=lambda: b'\x00' * 38)
    header_key: bytes = field(default_factory=lambda: b'\x00' * 16)

    struct = struct.Struct("<8sII36s12x4s4xI8xI4xI4xIII10s38s16s80x")

    def check_magic(self):
        return self.magic == b'NPUMDIMG'


@dataclass
class PSARBlockInfo(Struct):
    values: Tuple[int, int, int, int, int, int, int, int]

    struct = struct.Struct("<IIIIIIII")

    @property
    def block_offset(self):
        t = self.values
        return t[4] ^ t[2] ^ t[3]

    @property
    def block_size(self):
        t = self.values
        return t[5] ^ t[1] ^ t[2]

    @property
    def block_flags(self):
        t = self.values
        return t[6] ^ t[0] ^ t[3]


@dataclass
class PS1TableEntry(Struct):
    block_offset: int
    block_size: int
    block_marker: int
    block_checksum: bytes = field(default_factory=lambda: b'\x00' * 16)

    @property
    def block_flags(self):
        return None

    struct = struct.Struct("<IHH16s8x")


@dataclass
class PGDHeader(Struct):
    magic: bytes  # Magic "PGD\0"
    version: int  # Version (0x01000000)
    encryption_mode: int  # Offset or (encryption mode + padding) (0x01000000)
    padding: int  # Padding (0x00000000)
    key: bytes = field(default_factory=lambda: bytes(16))  # AES-128 bit hash key for header decryption
    hash_key: bytes = field(default_factory=lambda: bytes(16))  # Generated hash from the key

    struct = struct.Struct("<4sIII16s16s")

    def check_magic(self):
        return self.magic == b"\x00PGD"

    @property
    def cipher_type(self):
        if self.encryption_mode == 1:
            return 1
        else:
            return 2

    @property
    def mac_type(self):
        if self.encryption_mode == 1:
            if self.version > 1:
                return 3
            return 1
        else:
            return 2

    @property
    def open_flag(self):
        flag = 2
        if self.encryption_mode == 1:
            flag |= 4

            if self.version > 1:
                flag |= 8
        return flag

@dataclass
class PGDSubHeader(Struct):
    encrypted_header: bytes = field(default_factory=lambda: bytes(48))  # 0x30 bytes of encrypted header
    file_hash: bytes = field(default_factory=lambda: bytes(16))  # File hash
    ioctl_hash: bytes = field(default_factory=lambda: bytes(16))  # Hash generated from sceIoIoctl key
    encrypted_ioctl_hash: bytes = field(default_factory=lambda: bytes(16))  # Encrypted hash from sceIoIoctl key
    data_hash: bytes = field(default_factory=lambda: bytes(16))  # Data hash
    encrypted_data_hash: bytes = field(default_factory=lambda: bytes(16))  # Encrypted data hash

    struct = struct.Struct("<48s16s16s16s16s16s")

    # Decrypted header properties
    _decrypted_header: bytes = field(default=None, init=False, repr=False, compare=False)

    def set_decrypted_header(self, decrypted_header: bytes):
        """Set the decrypted header data after decryption"""
        if len(decrypted_header) != 48:
            raise ValueError("Decrypted header must be 48 bytes")
        self._decrypted_header = decrypted_header

    @property
    def decrypted_header(self) -> bytes:
        """Get the decrypted header if available"""
        return self._decrypted_header

    @property
    def hash_key(self) -> Optional[bytes]:
        """First field from decrypted header (expected to be NULL)"""
        if self._decrypted_header:
            return self._decrypted_header[:0x10]
        return None

    @property
    def null_field(self) -> Optional[int]:
        """First field from decrypted header (expected to be NULL)"""
        if self._decrypted_header:
            return struct.unpack("<I", self._decrypted_header[0x10:0x14])[0]
        return None

    @property
    def data_size(self) -> Optional[int]:
        """Decrypted data size from decrypted header"""
        if self._decrypted_header:
            return struct.unpack("<I", self._decrypted_header[0x14:0x18])[0]
        return None

    @property
    def chunk_size(self) -> Optional[int]:
        """Decrypting chunk size from decrypted header"""
        if self._decrypted_header:
            return struct.unpack("<I", self._decrypted_header[0x18:0x1C])[0]
        return None

    @property
    def data_hash_address(self) -> Optional[int]:
        """Data hash address from decrypted header"""
        if self._decrypted_header:
            return struct.unpack("<I", self._decrypted_header[0x1C:0x20])[0]
        return None

    @property
    def header_hash_key(self) -> Optional[bytes]:
        """Hash key from decrypted header (16 bytes)"""
        if self._decrypted_header:
            return self._decrypted_header[0x26:0x42]
        return None

    @property
    def align_size(self):
        if self.data_size:
            return (self.data_size + 15) & ~15
        return None

    @property
    def table_offset(self):
        if not self.data_hash_address or not self.align_size:
            return None
        return self.data_hash_address + self.align_size

    @property
    def block_nr(self):
        if not self.align_size or not self.chunk_size:
            return None
        block_nr = (self.align_size + self.chunk_size - 1) & ~(self.chunk_size - 1)
        return block_nr // self.chunk_size


@dataclass
class PSTitleImgHeader(Struct):
    """Header structure for PlayStation title images (PSTITLEIMG)"""

    magic: bytes  # Magic identifier "PSTITLEIMG000000"
    padding1: bytes = field(default_factory=lambda: bytes(0x1F0))  # 496 bytes padding
    discs_start_offsets: List[int] = field(default_factory=lambda: [0] * 25)  # Start positions for up to 25 discs
    game_id: bytes = field(default_factory=lambda: bytes(16))  # Game identifier (e.g. "_SLES_12345")
    padding2: bytes = field(default_factory=lambda: bytes(24))  # 24 bytes padding
    unknown1: bytes = field(default_factory=lambda: bytes(128))  # 128 bytes of unknown data
    unknown2: bytes = field(default_factory=lambda: bytes(128))  # 128 bytes related to data from 0x390
    unknown3: int = 0  # 4 bytes of unknown data
    unknown4: bytes = field(default_factory=lambda: bytes(62))  # 62 bytes related to data from 0x30C
    padding3: bytes = field(default_factory=lambda: bytes(2))  # 2 bytes padding
    unknown5: int = 0  # 4 bytes of unknown data
    padding4: bytes = field(default_factory=lambda: bytes(44))  # 44 bytes padding

    struct = struct.Struct("<16s496s100s16s24s128s128sI62s2sI44s")

    def check_magic(self):
        return self.magic == b"PSTITLEIMG000000"

    def __post_init__(self):
        """Process disc offsets after initialization"""
        if isinstance(self.discs_start_offsets, bytes) and len(self.discs_start_offsets) >= 20:
            offset_list = []
            for i in range(0, 20, 4):
                value = int.from_bytes(self.discs_start_offsets[i:i + 4], byteorder='little')
                if value == 0:
                    break
                offset_list.append(value)
            self.discs_start_offsets = offset_list


@dataclass
class CueEntry(Struct):
    type: int  # Track Type = 0x41 for DATA, 0x01 for CDDA, 0xA2 for lead out
    number: int  # Track Number (0x01 to 0x99)
    I0m: int  # INDEX 00 MM
    I0s: int  # INDEX 00 SS
    I0f: int  # INDEX 00 FF
    I1m: int  # INDEX 01 MM
    I1s: int  # INDEX 01 SS
    I1f: int  # INDEX 01 FF

    struct = struct.Struct("<HBBBBxBBB")  # Using big-endian format to match other structs

    @property
    def is_valid_track(self):
        return self.type in [0x01, 0x21, 0x41, 0x61]

    @staticmethod
    def bcd_to_decimal(bcd_value):
        """Convert BCD (Binary-Coded Decimal) to standard decimal"""
        return 10 * (bcd_value >> 4) + (bcd_value & 0xF)

    def get_index0_time(self, gap=0):
        """Get INDEX 00 time in decimal MM:SS:FF format with optional gap adjustment"""
        mm = self.bcd_to_decimal(self.I0m)
        ss = max(0, self.bcd_to_decimal(self.I0s) - gap)  # Ensure we don't go negative
        ff = self.bcd_to_decimal(self.I0f)
        return (mm, ss, ff)

    def get_index1_time(self, gap=0):
        """Get INDEX 01 time in decimal MM:SS:FF format with optional gap adjustment"""
        mm = self.bcd_to_decimal(self.I1m)
        ss = max(0, self.bcd_to_decimal(self.I1s) - gap)  # Ensure we don't go negative
        ff = self.bcd_to_decimal(self.I1f)
        return (mm, ss, ff)

    def get_index0_sectors(self, gap=0):
        """Convert INDEX 00 time to total sectors (assuming 75 frames per second)"""
        mm, ss, ff = self.get_index0_time(gap)
        return (mm * 60 + ss) * 75 + ff

    def get_index1_sectors(self, gap=0):
        """Convert INDEX 01 time to total sectors (assuming 75 frames per second)"""
        mm, ss, ff = self.get_index1_time(gap)
        return (mm * 60 + ss) * 75 + ff

    def get_index0_str(self, gap=0):
        """Get INDEX 00 time as a formatted string (MM:SS:FF)"""
        mm, ss, ff = self.get_index0_time(gap)
        return f"{mm:02d}:{ss:02d}:{ff:02d}"

    def get_index1_str(self, gap=0):
        """Get INDEX 01 time as a formatted string (MM:SS:FF)"""
        mm, ss, ff = self.get_index1_time(gap)
        return f"{mm:02d}:{ss:02d}:{ff:02d}"


@dataclass
class NPDHeader(Struct):
    magic: bytes
    version: int
    license: int
    app_type: int
    content_id: List[int] = field(default_factory=lambda: [0] * 0x30)
    digest: List[int] = field(default_factory=lambda: [0] * 0x10)
    title_hash: List[int] = field(default_factory=lambda: [0] * 0x10)
    dev_hash: List[int] = field(default_factory=lambda: [0] * 0x10)
    activate_time: int = 0
    expire_time: int = 0

    struct = struct.Struct(">Iiii48s16s16s16sqq")

    def check_magic(self):
        return self.magic == b"NPD\0"


@dataclass
class EDATHeader(Struct):
    flags: int
    block_size: int
    file_size: int

    struct = struct.Struct(">iiQ")


@dataclass
class IsoBinEncMeta(Struct):
    sha1: bytes = field(default_factory=lambda: b'\x00' * 20)
    block_id: int = 0

    struct = struct.Struct(">20sI8x")
