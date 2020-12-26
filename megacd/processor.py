import logging
import os

from common.processor import BaseIsoProcessor

LOGGER = logging.getLogger(__name__)


class MegaCDIsoProcessor(BaseIsoProcessor):
    def get_disc_type(self):
        return {"disc_type": "cdr"}

    def hash_exe(self):
        return {}

    def get_exe_filename(self):
        # boot executable may not be possible to get as its done by the ip loader.
        return


    def get_extra_fields(self):
        fp = self.iso_path_reader.fp
        fp.seek(0x50)
        header_info = {
             "header_release_date": fp.read(8),
         }

        fp.seek(0x110)
        header_info["header_maker_id"] = fp.read(8)
        fp.seek(0x120)
        header_info["header_title"] = fp.read(96)
        fp.seek(0x180)
        header_info["header_product_number"] = fp.read(16)
        fp.seek(0x1F0)
        header_info["header_regions"] = fp.read(3)

        header_info = {
            header_key: header_item.decode(errors="replace").strip()
            for header_key, header_item in header_info.items()
        }

        return header_info