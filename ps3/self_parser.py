import dataclasses
import io
import struct
import zlib
from dataclasses import dataclass

from Crypto.Cipher import AES
from Crypto.Util import Counter


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
class SceHeader(Struct):
    magic: bytes = b''
    version: int = 0
    attribute: int = 0
    category: int = 0
    ext_header_size: int = 0
    file_offset: int = 0
    file_size: int = 0

    struct = struct.Struct(">4sIHHIQQ")

    def check_magic(self):
        return self.magic == b"SCE\0"


@dataclass
class SelfHeader(Struct):
    ext_hdr_version: int = 0
    program_identification_hdr_offset: int = 0
    elf_hdr_offset: int = 0
    program_hdr_offset: int = 0
    section_hdr_offset: int = 0
    segment_ext_hdr_offset: int = 0
    version_hdr_offset: int = 0
    supplemental_hdr_offset: int = 0
    supplemental_hdr_size: int = 0
    pad: int = 0

    struct = struct.Struct(">9Q")


@dataclass
class SCEVersionHeader(Struct):
    subheader_type: int = 0
    present: int = 0
    size: int = 0
    unknown: int = 0

    struct = struct.Struct(">IIII")


@dataclass
class SCEVersionBody(Struct):
    segment_id: int = 0
    unknown_2: int = 0  # 0x1
    unknown_3: int = 0
    unknown_4: int = 0  # ?Number of sections?
    unknown_5: int = 0
    offset: int = 0
    data_size: int = 0

    struct = struct.Struct(">HHIIIQQ")


@dataclass
class ProgramIdentificationHeader(Struct):
    program_authority_id: int = 0
    program_vender_id: int = 0
    program_type: int = 0
    program_sceversion: int = 0
    padding: int = 0

    struct = struct.Struct(">QIIQQ")


@dataclass
class CertificationHeader(Struct):
    sign_offset: int = 0
    sign_algorithm: int = 0
    cert_entry_num: int = 0
    attr_entry_num: int = 0
    optional_header_size: int = 0
    pad: int = 0

    struct = struct.Struct(">QIIIIQ")


@dataclass
class SegmentCertHeader(Struct):
    segment_offset: int = 0
    segment_size: int = 0
    segment_type: int = 0
    segment_id: int = 0
    sign_algorithm: int = 0
    sign_idx: int = 0
    enc_algorithm: int = 0
    key_idx: int = 0
    iv_idx: int = 0
    comp_algorithm: int = 0

    struct = struct.Struct(">QQIIIIIIII")


@dataclass
class Attributes(Struct):
    key: bytearray = bytearray(0x10)
    iv: bytearray = bytearray(0x10)

    struct = struct.Struct(">16s16s")


@dataclass
class EncryptionRootHeader(Struct):
    key: bytearray = bytearray(0x10)
    key_pad: bytearray = bytearray(0x10)
    iv: bytearray = bytearray(0x10)
    iv_pad: bytearray = bytearray(0x10)

    struct = struct.Struct(">16s16s16s16s")


@dataclass
class ElfHeader(Struct):
    e_magic: bytes = b''  # must be \x7FELF
    e_class: int = 0  # must be ELFCLASS64 (0x02)
    e_data: int = 0  # must be ELFDATA2MSB (0x02)
    e_elfver: int = 0  # must be 0x01
    e_os_abi: int = 0  # must be 0x66 (ELFOSABI_CELL_LV2)
    e_abi_ver: int = 0  # must be 0x0
    e_type: int = 0  # object file type
    e_machine: int = 0  # machine type
    e_version: int = 0  # object file version
    e_entry: int = 0  # entry point address
    e_phoff: int = 0  # program header offset
    e_shoff: int = 0  # section header offset
    e_flags: int = 0  # processor-specific flags
    e_ehsize: int = 0  # ELF header size
    e_phentsize: int = 0  # size of program header entry
    e_phnum: int = 0  # number of program header entries
    e_shentsize: int = 0  # size of section header entry
    e_shnum: int = 0  # number of section header entries
    e_shstrndx: int = 0  # section name string table index

    struct = struct.Struct(">4sBBBBQHHIQQQIHHHHHH")

    def check_magic(self):
        return self.e_magic == b'\x7FELF'


@dataclass
class ElfHeader32(Struct):
    e_magic: bytes = b''  # must be \x7FELF
    e_class: int = 0  # must be ELFCLASS32 (0x02)
    e_data: int = 0  # must be ELFDATA2MSB (0x02)
    e_elfver: int = 0  # must be 0x01
    e_os_abi: int = 0  # must be 0x66 (ELFOSABI_CELL_LV2)
    e_abi_ver: int = 0  # must be 0x0
    e_type: int = 0  # object file type
    e_machine: int = 0  # machine type
    e_version: int = 0  # object file version
    e_entry: int = 0  # entry point address
    e_phoff: int = 0  # program header offset
    e_shoff: int = 0  # section header offset
    e_flags: int = 0  # processor-specific flags
    e_ehsize: int = 0  # ELF header size
    e_phentsize: int = 0  # size of program header entry
    e_phnum: int = 0  # number of program header entries
    e_shentsize: int = 0  # size of section header entry
    e_shnum: int = 0  # number of section header entries
    e_shstrndx: int = 0  # section name string table index

    struct = struct.Struct(">4sBBBBQHHIIIIIHHHHHH")

    def check_magic(self):
        return self.e_magic == b'\x7FELF'

@dataclass
class ProgramSegmentHeader(Struct):
    p_type: int = 0  # Segment type
    p_flags: int = 0  # Segment flags
    p_offset: int = 0  # Segment file offset
    p_vaddr: int = 0  # Segment virtual address
    p_paddr: int = 0  # Segment physical address
    p_filesz: int = 0  # Segment size in file
    p_memsz: int = 0  # Segment size in memory
    p_align: int = 0  # Segment alignment

    struct = struct.Struct(">IIQQQQQQ")


@dataclass
class ProgramSegmentHeader32(Struct):
    p_type: int = 0  # Segment type
    p_offset: int = 0  # Segment file offset
    p_vaddr: int = 0  # Segment virtual address
    p_paddr: int = 0  # Segment physical address
    p_filesz: int = 0  # Segment size in file
    p_memsz: int = 0  # Segment size in memory
    p_flags: int = 0  # Segment flags
    p_align: int = 0  # Segment alignment

    struct = struct.Struct(">IIIIIIII")


@dataclass
class SegmentExtendedHeader(Struct):
    offset: int = 0
    size: int = 0
    comp_algorithm: int = 0  # 1 = plain, 2 = zlib
    unknown: int = 0
    encrypted: int = 0

    struct = struct.Struct('>QQIIQ')


@dataclass
class ElfSectionHeader(Struct):
    sh_name: int = 0
    sh_type: int = 0
    sh_flags: int = 0
    sh_addr: int = 0
    sh_offset: int = 0
    sh_size: int = 0
    sh_link: int = 0
    sh_info: int = 0
    sh_addralign: int = 0
    sh_entsize: int = 0

    struct = struct.Struct(">IIQQQQIIQQ")


@dataclass
class ElfSectionHeader32(Struct):
    sh_name: int = 0
    sh_type: int = 0
    sh_flags: int = 0
    sh_addr: int = 0
    sh_offset: int = 0
    sh_size: int = 0
    sh_link: int = 0
    sh_info: int = 0
    sh_addralign: int = 0
    sh_entsize: int = 0

    struct = struct.Struct(">IIIIIIIIII")


class SELFDecrypter:
    apploader_keys = {
        0x0000: [
            "95F50019E7A68E341FA72EFDF4D60ED376E25CF46BB48DFDD1F080259DC93F04",
            "4A0955D946DB70D691A640BB7FAECC4C",
        ],
        0x0001: [
            "79481839C406A632BDB4AC093D73D99AE1587F24CE7E69192C1CD0010274A8AB",
            "6F0F25E1C8C4B7AE70DF968B04521DDA",
        ],
        0x0002: [
            "4F89BE98DDD43CAD343F5BA6B1A133B0A971566F770484AAC20B5DD1DC9FA06A",
            "90C127A9B43BA9D8E89FE6529E25206F",
        ],
        0x0003: [
            "C1E6A351FCED6A0636BFCB6801A0942DB7C28BDFC5E0A053A3F52F52FCE9754E",
            "E0908163F457576440466ACAA443AE7C",
        ],
        0x0004: [
            "838F5860CF97CDAD75B399CA44F4C214CDF951AC795298D71DF3C3B7E93AAEDA",
            "7FDBB2E924D182BB0D69844ADC4ECA5B",
        ],
        0x0005: [
            "C109AB56593DE5BE8BA190578E7D8109346E86A11088B42C727E2B793FD64BDC",
            "15D3F191295C94B09B71EBDE088A187A",
        ],
        0x0006: [
            "6DFD7AFB470D2B2C955AB22264B1FF3C67F180983B26C01615DE9F2ECCBE7F41",
            "24BD1C19D2A8286B8ACE39E4A37801C2",
        ],
        0x0007: [
            "945B99C0E69CAF0558C588B95FF41B232660ECB017741F3218C12F9DFDEEDE55",
            "1D5EFBE7C5D34AD60F9FBC46A5977FCE",
        ],
        0x0008: [
            "2C9E8969EC44DFB6A8771DC7F7FDFBCCAF329EC3EC070900CABB23742A9A6E13",
            "5A4CEFD5A9C3C093D0B9352376D19405",
        ],
        0x0009: [
            "F69E4A2934F114D89F386CE766388366CDD210F1D8913E3B973257F1201D632B",
            "F4D535069301EE888CC2A852DB654461",
        ],
        0x000A: [
            "29805302E7C92F204009161CA93F776A072141A8C46A108E571C46D473A176A3",
            "5D1FAB844107676ABCDFC25EAEBCB633",
        ],
        0x000B: [
            "A4C97402CC8A71BC7748661FE9CE7DF44DCE95D0D58938A59F47B9E9DBA7BFC3",
            "E4792F2B9DB30CB8D1596077A13FB3B5",
        ],
        0x000C: [
            "9814EFFF67B7074D1B263BF85BDC8576CE9DEC914123971B169472A1BC2387FA",
            "D43B1FA8BE15714B3078C23908BB2BCA",
        ],
        0x000D: [
            "03B4C421E0C0DE708C0F0B71C24E3EE04306AE7383D8C5621394CCB99FF7A194",
            "5ADB9EAFE897B54CB1060D6885BE22CF",
        ],
        0x000E: [
            "39A870173C226EB8A3EEE9CA6FB675E82039B2D0CCB22653BFCE4DB013BAEA03",
            "90266C98CBAA06C1BF145FF760EA1B45",
        ],
        0x000F: [
            "FD52DFA7C6EEF5679628D12E267AA863B9365E6DB95470949CFD235B3FCA0F3B",
            "64F50296CF8CF49CD7C643572887DA0B",
        ],
        0x0010: [
            "A5E51AD8F32FFBDE808972ACEE46397F2D3FE6BC823C8218EF875EE3A9B0584F",
            "7A203D5112F799979DF0E1B8B5B52AA4",
        ],
        0x0011: [
            "0F8EAB8884A51D092D7250597388E3B8B75444AC138B9D36E5C7C5B8C3DF18FD",
            "97AF39C383E7EF1C98FA447C597EA8FE",
        ],
        0x0013: [
            "DBF62D76FC81C8AC92372A9D631DDC9219F152C59C4B20BFF8F96B64AB065E94",
            "CB5DD4BE8CF115FFB25801BC6086E729",
        ],
        0x0014: [
            "491B0D72BB21ED115950379F4564CE784A4BFAABB00E8CB71294B192B7B9F88E",
            "F98843588FED8B0E62D7DDCB6F0CECF4",
        ],
        0x0016: [
            "A106692224F1E91E1C4EBAD4A25FBFF66B4B13E88D878E8CD072F23CD1C5BF7C",
            "62773C70BD749269C0AFD1F12E73909E",
        ],
        0x0017: [
            "4E104DCE09BA878C75DA98D0B1636F0E5F058328D81419E2A3D22AB0256FDF46",
            "954A86C4629E116532304A740862EF85",
        ],
        0x0018: [
            "1F876AB252DDBCB70E74DC4A20CD8ED51E330E62490E652F862877E8D8D0F997",
            "BF8D6B1887FA88E6D85C2EDB2FBEC147",
        ],
        0x0019: [
            "3236B9937174DF1DC12EC2DD8A318A0EA4D3ECDEA5DFB4AC1B8278447000C297",
            "6153DEE781B8ADDC6A439498B816DC46",
        ],
        0x001A: [
            "5EFD1E9961462794E3B9EF2A4D0C1F46F642AAE053B5025504130590E66F19C9",
            "1AC8FA3B3C90F8FDE639515F91B58327",
        ],
        0x001B: [
            "66637570D1DEC098467DB207BAEA786861964D0964D4DBAF89E76F46955D181B",
            "9F7B5713A5ED59F6B35CD8F8A165D4B8",
        ],
        0x001C: [
            "CFF025375BA0079226BE01F4A31F346D79F62CFB643CA910E16CF60BD9092752",
            "FD40664E2EBBA01BF359B0DCDF543DA4",
        ],
        0x001D: [
            "D202174EB65A62048F3674B59EF6FE72E1872962F3E1CD658DE8D7AF71DA1F3E",
            "ACB9945914EBB7B9A31ECE320AE09F2D",
        ],
    }

    def __init__(self, fp):
        self.fp = fp
        self.sce_hdr = None
        self.elf_hdr = None
        self.encryption_root_header = None
        self.cert_header = None
        self.segment_cert_header = []
        self.data_keys = None
        self.self_header = None
        self.key_v = None
        self.segment_headers = []
        self.segment_ext_table = []

    def load_headers(self):
        # Read SCE header.
        self.fp.seek(0)
        self.sce_hdr = SceHeader.unpack(self.fp.read(SceHeader.struct.size))

        # Check SCE magic.
        if not self.sce_hdr.check_magic():
            print("Not a SELF file!")
            return False

        # Read SELF header.
        self.self_header = SelfHeader.unpack(self.fp.read(SelfHeader.struct.size))

        # Determine if this is a 32 or 64 bit ELF
        self.fp.seek(self.self_header.elf_hdr_offset)
        is_elf32 = self.fp.read(8)[4] == 1

        # Read ELF header.
        self.fp.seek(self.self_header.elf_hdr_offset)
        elf_header_class = ElfHeader32 if is_elf32 else ElfHeader
        self.elf_hdr = elf_header_class.unpack(self.fp.read(elf_header_class.struct.size))

        # Read ELF program headers.
        self.program_headers = []
        if self.elf_hdr.e_phoff == 0 and self.elf_hdr.e_phnum:
            print("ELF program header offset is null!")
            return False

        self.fp.seek(self.self_header.program_hdr_offset)
        program_header_class = ProgramSegmentHeader32 if is_elf32 else ProgramSegmentHeader
        for _ in range(self.elf_hdr.e_phnum):
            program_headers = program_header_class.unpack(self.fp.read(program_header_class.struct.size))
            self.program_headers.append(program_headers)

        # Read segment ext header.
        self.fp.seek(self.self_header.segment_ext_hdr_offset)
        for _ in range(self.elf_hdr.e_phnum):
            segment_ext_header = SegmentExtendedHeader.unpack(self.fp.read(SegmentExtendedHeader.struct.size))
            self.segment_ext_table.append(segment_ext_header)

        # Read SCE version info.
        self.fp.seek(self.self_header.version_hdr_offset)
        self.scev_info = SCEVersionHeader.unpack(self.fp.read(SCEVersionHeader.struct.size))
        if self.scev_info.present:
            self.scev_version = SCEVersionBody.unpack(self.fp.read(SCEVersionBody.struct.size))

        # Read ELF section headers.
        self.segment_headers = []
        if self.elf_hdr.e_shoff == 0 and self.elf_hdr.e_shnum:
            print("ELF section header offset is null!")
            return True

        self.fp.seek(self.self_header.section_hdr_offset)
        segment_header_class = ElfSectionHeader32 if is_elf32 else ElfSectionHeader
        for _ in range(self.elf_hdr.e_shnum):
            shdr = segment_header_class.unpack(self.fp.read(segment_header_class.struct.size))
            self.segment_headers.append(shdr)

        return True

    def load_metadata(self):
        # Check DEBUG flag.
        if self.sce_hdr.attribute & 0x8000 == 0x8000:
            # Debug SELF, don't bother with encryption
            # Generate dummy Segment Certification Header entries that mirror the Segment Extended Header
            for idx, segexthdr in enumerate(self.segment_ext_table):
                self.segment_cert_header.append(SegmentCertHeader(
                    segment_offset=segexthdr.offset,
                    segment_size=segexthdr.size,
                    segment_type=2,
                    segment_id=idx,
                    sign_algorithm=0,
                    sign_idx=0xFFFFFFFF,
                    enc_algorithm=1,
                    key_idx=0xFFFFFFFF,
                    iv_idx=0xFFFFFFFF,
                    comp_algorithm=segexthdr.comp_algorithm,
                ))
            # Add the sceversion section if present
            if self.scev_info.present:
                self.segment_cert_header.append(SegmentCertHeader(
                    segment_offset=self.scev_version.offset,
                    segment_size=self.scev_version.data_size,
                    segment_type=3,
                    segment_id=self.scev_version.segment_id,
                    sign_algorithm=0,
                    sign_idx=0xFFFFFFFF,
                    enc_algorithm=1,
                    key_idx=0xFFFFFFFF,
                    iv_idx=0xFFFFFFFF,
                    comp_algorithm=1,
                ))
            # Add section header
            self.segment_cert_header.append(SegmentCertHeader(
                segment_offset=self.self_header.section_hdr_offset,
                segment_size=ElfSectionHeader.struct.size * self.elf_hdr.e_shnum,
                segment_type=1,
                segment_id=3,
                sign_algorithm=0,
                sign_idx=0xFFFFFFFF,
                enc_algorithm=1,
                key_idx=0xFFFFFFFF,
                iv_idx=0xFFFFFFFF,
                comp_algorithm=1,
            ))
            return

        meta_headers_and_section_size = self.sce_hdr.file_offset - (
                SceHeader.struct.size + self.sce_hdr.ext_header_size + EncryptionRootHeader.struct.size)

        # Locate and read the Encryption root header.
        self.fp.seek(self.sce_hdr.ext_header_size + SceHeader.struct.size)
        metadata_info = self.fp.read(EncryptionRootHeader.struct.size)

        # Locate and read the encrypted metadata header and section header.
        self.fp.seek(self.sce_hdr.ext_header_size + SceHeader.struct.size + EncryptionRootHeader.struct.size)
        metadata_headers = self.fp.read(meta_headers_and_section_size)

        # Find the right keyset from the key vault.
        try:
            metadata_key = bytes.fromhex(self.apploader_keys[self.sce_hdr.attribute][0])
            metadata_iv = bytes.fromhex(self.apploader_keys[self.sce_hdr.attribute][1])
        except KeyError:
            print("Could not find decryption key")
            return

        # Decrypt the metadata info.
        aes = AES.new(metadata_key, AES.MODE_CBC, metadata_iv)
        metadata_info = aes.decrypt(metadata_info)

        # Load the metadata info.
        self.encryption_root_header = EncryptionRootHeader.unpack(metadata_info)

        # If the padding is not NULL for the key or iv fields, the metadata info
        # is not properly decrypted.
        if self.encryption_root_header.key_pad[0] != 0x00 or self.encryption_root_header.iv_pad[0] != 0x00:
            print("Failed to decrypt SCE metadata info!")
            return

        # Perform AES-CTR encryption on the metadata headers.
        aes = AES.new(self.encryption_root_header.key, AES.MODE_CTR,
                      counter=Counter.new(128, initial_value=int.from_bytes(self.encryption_root_header.iv, "big")))
        metadata_headers = io.BytesIO(aes.encrypt(metadata_headers))

        # Load the metadata header.
        self.cert_header = CertificationHeader.unpack(metadata_headers.read(CertificationHeader.struct.size))

        # Load the metadata section headers.
        for i in range(self.cert_header.cert_entry_num):
            self.segment_cert_header.append(
                SegmentCertHeader.unpack(metadata_headers.read(SegmentCertHeader.struct.size)))

        # Copy the decrypted data keys.
        data_keys_length = self.cert_header.attr_entry_num * 0x10
        self.data_keys = bytearray(metadata_headers.read(data_keys_length))

    def decrypt_data(self, segment_cert_header):
        # Get the key and iv from the previously stored key buffer.
        data_key_offset = segment_cert_header.key_idx * 0x10
        data_iv_offset = segment_cert_header.iv_idx * 0x10
        data_key = self.data_keys[data_key_offset:data_key_offset + 0x10]
        data_iv = self.data_keys[data_iv_offset:data_iv_offset + 0x10]

        # Seek to the section data offset and read the encrypted data.
        self.fp.seek(segment_cert_header.segment_offset)
        buf = self.fp.read(segment_cert_header.segment_size)

        # Perform AES-CTR encryption on the data blocks.
        aes = AES.new(data_key, AES.MODE_CTR, counter=Counter.new(128, initial_value=int.from_bytes(data_iv, "big")))
        return aes.encrypt(buf)

    def get_decrypted_elf(self):
        # Allocate a buffer to store decrypted data.
        elf = io.BytesIO()

        # Write the ELF header
        elf.write(self.elf_hdr.pack())

        # Write program headers.
        for phdr in self.program_headers:
            elf.write(phdr.pack())

        # Parse the metadata section headers to find the offsets of encrypted data.
        for segment_cert_header in self.segment_cert_header:
            if segment_cert_header.segment_type < 2:
                continue

            # Check if this is an encrypted section.
            # Make sure the key and iv are not out of boundaries.
            if segment_cert_header.enc_algorithm == 3 and \
                    segment_cert_header.key_idx <= self.cert_header.attr_entry_num - 1 and \
                    segment_cert_header.iv_idx <= self.cert_header.attr_entry_num:
                segment_data = self.decrypt_data(segment_cert_header)
            else:
                self.fp.seek(segment_cert_header.segment_offset)
                segment_data = self.fp.read(segment_cert_header.segment_size)

            # Decompress if necessary.
            if segment_cert_header.comp_algorithm == 2:
                # Use zlib uncompress on the new buffer.
                segment_data = zlib.decompress(segment_data)

            if segment_cert_header.segment_type == 2:
                elf.seek(self.program_headers[segment_cert_header.segment_id].p_offset)
            elif segment_cert_header.segment_type == 3:
                elf.seek(self.segment_headers[segment_cert_header.segment_id].sh_offset)
            else:
                raise Exception(f"Unsupported segment cert header type {segment_cert_header.segment_type:d}")

            elf.write(segment_data)

        # Write section headers.
        if self.self_header.section_hdr_offset != 0:
            elf.seek(self.elf_hdr.e_shoff)

            for shdr in self.segment_headers:
                elf.write(shdr.pack())

        elf.seek(0)
        return elf
