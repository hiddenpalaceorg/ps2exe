import binascii
import datetime
import logging
import struct
from os.path import basename

import xxhash

from common.processor import BaseIsoProcessor
from psp.chained_subimg_reader import ChainedSubImgReader

LOGGER = logging.getLogger(__name__)


class PspIsoProcessor(BaseIsoProcessor):
    SFO_HEADER_BYTES = 20

    def __init__(self, iso_path_reader, *args):
        sub_imgs = {}
        self.disc_type = "umd"
        for file in iso_path_reader.iso_iterator(iso_path_reader.get_root_dir(), recursive=False):
            file_basename = basename(iso_path_reader.get_file_path(file))
            if file_basename.startswith("USER_L") and file_basename.endswith(".IMG"):
                sub_imgs[file_basename] = iso_path_reader.open_file(file)

        if sub_imgs:
            self.disc_type = "dvdr"
            sub_imgs = list(dict(sub_imgs).values())
            fp = ChainedSubImgReader(sub_imgs)
            from common.factory import IsoProcessorFactory
            iso_path_reader = IsoProcessorFactory.get_iso_path_reader(fp)

        super().__init__(iso_path_reader, *args)

    def get_disc_type(self):
        return {"disc_type": self.disc_type}

    def get_exe_filename(self):
        return "/PSP_GAME/SYSDIR/EBOOT.BIN"

    def get_file_hashes(self):
        file_hashes = {}
        root = self.iso_path_reader.get_root_dir()
        for file in self.iso_path_reader.iso_iterator(root, recursive=True):
            file_path = self.iso_path_reader.get_file_path(file)

            if file_path.startswith("/PSP_GAME/SYSDIR/UPDATE/"):
                continue

            if file_hash := self.iso_path_reader.get_file_hash(file, xxhash.xxh64):
                file_hashes[file_path] = file_hash.digest()
        return file_hashes


    def get_most_recent_file(self):
        most_recent_file_date = datetime.datetime.min
        most_recent_file_date = most_recent_file_date.replace(tzinfo=datetime.timezone.utc)
        most_recent_file = None
        root = self.iso_path_reader.get_root_dir()
        for file in self.iso_path_reader.iso_iterator(root, recursive=True):
            if self.iso_path_reader.get_file_path(file).startswith("/PSP_GAME/SYSDIR/UPDATE/"):
                continue

            file_date = self.iso_path_reader.get_file_date(file)

            if file_date > most_recent_file_date:
                most_recent_file = file
                most_recent_file_date = file_date
        return most_recent_file

    def get_extra_fields(self):
        self.get_exe_filename = lambda: "/PSP_GAME/SYSDIR/BOOT.BIN"
        alt_exe_hash = super().hash_exe()

        param_sfo = self.iso_path_reader.get_file("/PSP_GAME/PARAM.SFO")
        with self.iso_path_reader.open_file(param_sfo) as f:
            header_raw = f.read(20)
            header = struct.unpack('<4s4BIII', header_raw)
            name_table_start = header[5]
            data_table_start = header[6]
            n_params = header[7]

            def_table_bytes = 16 * n_params
            name_table_bytes = data_table_start - name_table_start
            def_table_padding = name_table_start - self.SFO_HEADER_BYTES - def_table_bytes

            def_table = []
            for e in range(n_params):
                def_rec_raw = f.read(16)
                def_record = struct.unpack('<HHIII', def_rec_raw)
                def_table.append(def_record)

            # Read past any padded space between the definition and name tables
            f.read(def_table_padding)

            # ---
            # Parse parameter names
            param_names = []
            for e in range(n_params):
                try:
                    p_name_bytes = def_table[e + 1][0] - def_table[e][0]
                except IndexError:
                    p_name_bytes = name_table_bytes - def_table[e][0]
                p_name = f.read(p_name_bytes)
                param_names.append(p_name.rstrip(b'\x00').decode())

            # ---
            # Parse parameter values
            param_values = []
            for e in range(n_params):
                v_type = def_table[e][1]
                v_total = def_table[e][3]

                value_raw = f.read(v_total)

                if v_type in (0x0204, 0x0004):
                    try:
                        value = value_raw.rstrip(b'\x00').decode()
                    except UnicodeDecodeError:
                        value = value_raw.rstrip(b'\x00').decode(encoding="cp1252", errors="ignore")
                elif v_type == 0x0404:
                    # Reverse index to read as little-endian
                    # NOTE: Method for raw string to int?
                    value_ascii = binascii.hexlify(value_raw[::-1])
                    value = int(value_ascii, 16)
                else:
                    continue

                param_values.append(value)

            params = dict(zip(param_names, param_values))

        return {
            "sfo_category": params.get("CATEGORY"),
            "sfo_disc_id": params.get("DISC_ID"),
            "sfo_disc_version": params.get("DISC_VERSION"),
            "sfo_parental_level": params.get("PARENTAL_LEVEL"),
            "sfo_psp_system_version": params.get("PSP_SYSTEM_VER"),
            "sfo_title": params.get("TITLE"),
            "alt_exe_filename": alt_exe_hash["exe_filename"],
            "alt_exe_date": alt_exe_hash["exe_date"],
            "alt_md5": alt_exe_hash["md5"],
        }

