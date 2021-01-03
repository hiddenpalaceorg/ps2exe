import datetime
import logging
import struct

from common.iso_path_reader.methods.compressed import CompressedPathReader
from common.processor import BaseIsoProcessor

LOGGER = logging.getLogger(__name__)

class XboxIsoProcessor(BaseIsoProcessor):
    def get_disc_type(self):
        if isinstance(self.iso_path_reader, CompressedPathReader):
            return {"disc_type": "hdd"}
        return {"disc_type": "dvdr"}

    def get_exe_filename(self):
        for exe in ["/default.xex", "/default.xbe"]:
            try:
                default_xbe = self.iso_path_reader.get_file(exe)
                with self.iso_path_reader.open_file(default_xbe):
                    return exe
            except FileNotFoundError:
                pass

        # could not find default.xbe in root, use first xbe we can find
        for file in self.iso_path_reader.iso_iterator(self.iso_path_reader.get_root_dir()):
            file_path = self.iso_path_reader.get_file_path(file)
            if file_path.lower().endswith(".xbe") or file_path.lower().endswith(".xex"):
                return file_path

    def get_most_recent_file_info(self, exe_date):
        return {}

    def get_extra_fields(self):
        try:
            result = {}
            with self.iso_path_reader.open_file(self.iso_path_reader.get_file(self.get_exe_filename())) as f:
                f.seek(0x104)
                base_addr, exe_time, cert_addr = struct.unpack("<I12xII", f.read(24))
                result["exe_date"] = datetime.datetime.utcfromtimestamp(exe_time)
                if (cert_addr > base_addr):
                    f.seek(cert_addr - base_addr)
                    cert_timestamp, cert_game_id, b, a, cert_title = struct.unpack("<4xIHss40s", f.read(52))
                    result["header_release_date"] = datetime.datetime.utcfromtimestamp(cert_timestamp)
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
            return result
        except FileNotFoundError:
            return {}

class Xbox360IsoProcessor(XboxIsoProcessor):
    def __init__(self, iso_path_reader, filename, system_type):
        LOGGER.warning("Xbox 360 Support is preliminary and does not process the executable contents yet")
        super().__init__(iso_path_reader, filename, system_type)

    def get_extra_fields(self):
            return {}