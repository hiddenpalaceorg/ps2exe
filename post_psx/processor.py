import binascii
import logging
import re
import struct

from common.processor import BaseIsoProcessor

LOGGER = logging.getLogger(__name__)


class PostPsxIsoProcessor(BaseIsoProcessor):
    exe_patterns = [
        re.compile(".*/EBOOT\.BIN$", re.IGNORECASE),
        re.compile(".*\.self$", re.IGNORECASE),
        re.compile(".*\.sprx$", re.IGNORECASE)
    ]
    SFO_HEADER_BYTES = 20

    @property
    def ignored_paths(self):
        return self.exe_patterns + [self.update_folder]

    @property
    def update_folder(self):
        raise NotImplementedError

    @property
    def sfo_path(self):
        raise NotImplementedError

    def get_extra_fields(self):
        params = self.parse_param_sfo()
        return {
            "sfo_category": params.get("CATEGORY"),
            "sfo_disc_id": params.get("TITLE_ID"),
            "sfo_disc_version": params.get("DISC_VERSION"),
            "sfo_parental_level": params.get("PARENTAL_LEVEL"),
            "sfo_psp_system_version": params.get("PS3_SYSTEM_VER"),
            "sfo_title": params.get("TITLE"),
        }

    def parse_param_sfo(self):
        LOGGER.info("Parsing param.sfo")
        param_sfo = self.iso_path_reader.get_file(self.sfo_path)
        with self.iso_path_reader.open_file(param_sfo) as f:
            header_raw = f.read(self.SFO_HEADER_BYTES)
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

            return dict(zip(param_names, param_values))
