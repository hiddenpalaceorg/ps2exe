import io
import logging
import os
import pathlib

from common.iso_path_reader.methods.base import IsoPathReader
from common.iso_path_reader.methods.chunked_hash_trait import ChunkedHashTrait
from post_psx.npdrm.pkg import Pkg
from post_psx.utils.edat import EdatFile
from utils import pycdlib
from utils.files import OffsetFile
from utils.pycdlib.decrypted_file_io import DecryptedFileIO

LOGGER = logging.getLogger(__name__)


class DecryptedFileReader(DecryptedFileIO):
    def __init__(self, ino, logical_block_size, pkg, entry):
        super().__init__(ino, logical_block_size, buffer_blocks=65536 // logical_block_size)
        self.pkg = pkg
        self.entry = entry
        self.pkg.init_cipher(ino.extent_location(), entry.key)

    def seek(self, offset, whence=0):
        super().seek(offset, whence)
        self.pkg.init_cipher(
            self._ctxt.ino.extent_location() + (self._offset // self.logical_block_size), self.entry.key
        )

    def decrypt_blocks(self, blocks):
        return self.pkg.decrypt(blocks)


class NPDRMPathReader(ChunkedHashTrait, IsoPathReader):
    volume_type = "npdrm"

    def __init__(self, iso: Pkg, fp, parent_container):
        super().__init__(iso, fp, parent_container)
        pkg_header = self.iso.pkg_header
        self.fp = OffsetFile(self.fp, pkg_header.data_offset, pkg_header.data_offset + pkg_header.data_size)
        self.edat_key = self.get_edat_key()

    def get_edat_key(self):
        edat_file = next((file for file in self.iso_iterator(self.get_root_dir(), recursive=True) if
                          self.get_file_path(file).lower().endswith(".edat")), None)
        if not edat_file:
            return

        edat_key = None
        file_dir = pathlib.Path(self.fp.name).parent
        try:
            title_id = self.iso.pkg_header.title_id.decode("utf-8")
            # Check for a rap file in the dir
            try:
                with self.parent_container.open_file(self.parent_container.get_file(str((file_dir / title_id).with_suffix(".rap")))) as f:
                    edat_key = EdatFile.rap_to_rif(f.read())
            except FileNotFoundError:
                pass
        except UnicodeDecodeError:
            pass

        if edat_key:
            if self.test_key(edat_key, edat_file):
                return edat_key
        else:
            test_edat_key = bytes.fromhex("0" * 32)
            if self.test_key(test_edat_key, edat_file):
                return test_edat_key

    def test_key(self, key, file):
        file_path = self.get_file_path(file)
        inode = pycdlib.inode.Inode()
        inode.parse(file.file_offset // 16, file.file_size, self.fp, 16)
        with DecryptedFileReader(inode, 16, self.iso, file) as f, \
                EdatFile(f, os.path.basename(file_path), key) as f:
            return f.decrypt_block(0, key) != -1

    def get_root_dir(self):
        return next(self.iso.entries()).directory

    def iso_iterator(self, base_dir, recursive=False, include_dirs=False):
        for entry in base_dir.entries:
            if self.is_directory(entry) and not include_dirs:
                continue
            yield entry

        if not recursive:
            return
        for dir in base_dir.directories.values():
            yield from self.iso_iterator(dir, recursive)


    def get_file(self, path):
        normalized_path = path.strip('/')

        for file in self.iso_iterator(self.get_root_dir(), recursive=True):
            if file.name_decoded == normalized_path:
                return file

        raise FileNotFoundError()

    def get_file_date(self, file):
        return None

    def get_file_path(self, file):
        return file.name_decoded

    def open_file(self, file):
        inode = pycdlib.inode.Inode()
        inode.parse(file.file_offset // 16, file.file_size, self.fp, 16)
        f = DecryptedFileReader(inode, 16, self.iso, file)
        file_path = self.get_file_path(file)
        if file_path.lower().endswith("edat"):
            f.__enter__()
            edat_file = EdatFile(f, os.path.basename(file_path), self.edat_key)
            if not edat_file.validate_npd_hashes(os.path.basename(file_path), edat_file.hash_key):
                LOGGER.warning("Could not validate header hashes for %s", file_path)
            if edat_file.edat_header.file_size == 0:
                f.__exit__()
                f = io.BytesIO(b"")
            elif not self.edat_key:
                LOGGER.warning("Could not locate decryption key for %s. File will not be decrypted", file_path)
            else:
                f = edat_file

        f.name = self.get_file_path(file)
        return f

    def get_file_sector(self, file):
        raise NotImplementedError

    def get_file_size(self, file):
        file_path = self.get_file_path(file)
        if file_path.lower().endswith("edat"):
            inode = pycdlib.inode.Inode()
            inode.parse(file.file_offset // 16, file.file_size, self.fp, 16)
            with DecryptedFileReader(inode, 16, self.iso, file) as f:
                edat_size = EdatFile(f, os.path.basename(file_path), self.edat_key).edat_header.file_size
                if edat_size == 0 or self.edat_key:
                    return edat_size
        return file.file_size

    def is_directory(self, file):
        return file.is_dir

    def get_pvd(self):
        return None

    def get_pvd_info(self):
        return {}

    @property
    def system_type(self):
        if self.iso.pkg_header.pkg_platform == self.iso.PKG_PLATFORM_TYPE_PS3:
            return "ps3"

        title_id = self.iso.pkg_header.title_id
        psp_title_ids = [b"UL", b"UC", b"G", b"H", b"W", b"Y"]
        ps3_title_ids = [b"BL", b"BC"]
        if title_id[0:2] in ps3_title_ids:
            return "ps3"
        elif any(title_id.startswith(tid) for tid in psp_title_ids):
            return "psp"
        elif title_id[0:3] == b"PCS":
            return "vita"

        if self.iso.pkg_ext_header:
            if self.iso.pkg_ext_header.pkg_key_id == 0x1:
                return "psp"
            elif self.iso.pkg_ext_header.pkg_key_id == 0xC0000002:
                return "vita"
