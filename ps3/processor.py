import hashlib
import logging
import re

import xxhash

from post_psx.processor import PostPsxIsoProcessor
from ps3.self_parser import SELFDecrypter

LOGGER = logging.getLogger(__name__)


class Ps3IsoProcessor(PostPsxIsoProcessor):
    update_folder = re.compile(".*PS3_UPDATE$", re.IGNORECASE)
    sfo_path = "/PS3_GAME/PARAM.SFO"

    @property
    def ignored_paths(self):
        paths = self.exe_patterns + [self.update_folder]
        paths.append(re.compile("(?!^\/PS3_GAME\/USRDIR\/)", re.IGNORECASE))
        return paths

    def get_disc_type(self):
        return {"disc_type": "bd-r"}

    def get_exe_filename(self):
        return "/PS3_GAME/USRDIR/EBOOT.BIN"

    def get_file_hashes(self, hash_type=xxhash.xxh64):
        file_hashes, alt_file_hashes, incomplete_files = super().get_file_hashes(hash_type)
        root = self.iso_path_reader.get_root_dir()
        for file in self.iso_path_reader.iso_iterator(root, recursive=True):
            file_path = self.iso_path_reader.get_file_path(file)

            if any(regex.match(file_path) for regex in self.exe_patterns):
                with self.iso_path_reader.open_file(file) as f:
                    decryptor = SELFDecrypter(f)
                    decryptor.load_headers()
                    decryptor.load_metadata()
                    elf = decryptor.get_decrypted_elf()
                    alt_file_hashes[file_path] = hash_type(elf.read()).digest()
        return file_hashes, alt_file_hashes, incomplete_files

    def _parse_exe(self, filename):
        result = {}
        with self.iso_path_reader.open_file(self.iso_path_reader.get_file(filename)) as f:
            decryptor = SELFDecrypter(f)
            decryptor.load_headers()
            result["exe_signing_type"] = "debug" if decryptor.sce_hdr.attribute & 0x8000 == 0x8000 else "retail"
            result["exe_num_symbols"] = 0
            for section in decryptor.segment_headers:
                if section.sh_type == 2:
                    result["exe_num_symbols"] = section.sh_size // 24
            decryptor.load_metadata()
            elf = decryptor.get_decrypted_elf()
            md5 = hashlib.md5(elf.read())
            result["alt_md5"] = md5.hexdigest()

        return result

    def get_extra_fields(self):
        params = self.parse_param_sfo()
        fields = {
            "sfo_category": params.get("CATEGORY"),
            "sfo_disc_id": params.get("TITLE_ID"),
            "sfo_disc_version": params.get("DISC_VERSION"),
            "sfo_parental_level": params.get("PARENTAL_LEVEL"),
            "sfo_psp_system_version": params.get("PS3_SYSTEM_VER"),
            "sfo_title": params.get("TITLE"),
        }
        return {**fields,  **self._parse_exe(self.get_exe_filename())}
