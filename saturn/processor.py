import logging
import os

from common.processor import BaseIsoProcessor

LOGGER = logging.getLogger(__name__)


class SaturnIsoProcessor(BaseIsoProcessor):
    def get_disc_type(self):
        return {"disc_type": "cdr"}

    def get_exe_filename(self):
        root = self.iso_path_reader.get_root_dir()
        exe_file = next(self.iso_path_reader.iso_iterator(root, recursive=False), None)
        if exe_file:
            return self.iso_path_reader.get_file_path(exe_file)


    def get_extra_fields(self):
        fp = self.iso_path_reader.fp
        fp.seek(0x10)
        header_info = {
            "header_maker_id": fp.read(16),
            "header_product_number": fp.read(10),
            "header_product_version": fp.read(6),
            "header_release_date": fp.read(8),
            "header_device_info": fp.read(8),
            "header_regions": fp.read(10),
        }
        fp.seek(22, os.SEEK_CUR)
        header_info["header_title"] = fp.read(112)

        header_info = {
            header_key: header_item.decode(errors="replace").strip()
            for header_key, header_item in header_info.items()
        }

        return header_info