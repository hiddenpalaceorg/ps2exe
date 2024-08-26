import struct

from dataclasses import dataclass, field
from typing import List

from ps3.self_parser import Struct


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
