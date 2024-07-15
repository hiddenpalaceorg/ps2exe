import datetime
import hashlib
import logging
import re

from common.processor import BaseIsoProcessor

LOGGER = logging.getLogger(__name__)

class GamecubeIsoProcessor(BaseIsoProcessor):
    SDK_STRING = b"Dolphin SDK"

    def get_disc_type(self):
        return {"disc_type": "nr"}

    def get_exe_filename(self):
        return "/main.dol"

    def get_most_recent_file_info(self, exe_date):
        return {}

    def hash_exe(self):
        exe_filename = self.get_exe_filename()
        LOGGER.info("Found exe: %s", exe_filename)

        try:
            exe = self.iso_path_reader.iso.dol
            exe._fileoffset = self.iso_path_reader.iso.bootheader.dolOffset
            exe.name = exe_filename
            md5 = self.iso_path_reader.get_file_hash(exe, algo=hashlib.md5).hexdigest()
            sections_with_dates = []
            dol_dates = []
            for section in self.iso_path_reader.iso.dol.sections:
                dol_data = section.data.read()
                if b"<< " + self.SDK_STRING in dol_data:
                    sections_with_dates.append(dol_data)
                if b"Kernel built" in dol_data:
                    sections_with_dates.append(dol_data)

            if sections_with_dates:
                dol_dates = []
                for dol_data in sections_with_dates:
                    dol_dates.extend([
                        datetime.datetime.strptime(date.decode(), '%b %d %Y %H:%M:%S')
                        for date in
                        re.findall(br"<< " + self.SDK_STRING + br" - .+? build: (.{20}).*>>", dol_data)
                    ])
                    dol_dates.extend([
                        datetime.datetime.strptime(date.decode(), '%b %d %Y\x00%H:%M:%S')
                        for date in
                        re.findall(br"Kernel built.*\x0A\x00\x00\x00(.{20})", dol_data)
                    ])
            LOGGER.info("md5 %s", md5)
        except:
            LOGGER.exception(f"Executable not found. exe filename: %s, files: %s,  iso: %s",
                           exe_filename, self.get_file_list(), self.filename)
            return {}

        return {
            "exe_filename": exe_filename,
            "exe_date": max(dol_dates) if dol_dates else None,
            "md5": md5,
        }

    def get_extra_fields(self):
        fp = self.iso_path_reader.fp
        fp.seek(0)
        header_info = {
            "header_maker_id": fp.read(6),
        }

        fp.seek(0x07)
        header_info["header_product_version"] = int(fp.read(1)[0])

        fp.seek(0x20)
        header_info["header_title"] = fp.read(64)

        header_info = {
            header_key: header_item.decode(errors="replace").strip().rstrip("\x00")
            if isinstance(header_item, bytes) else header_item
            for header_key, header_item in header_info.items()
        }
        header_info["alt_exe_date"] = datetime.datetime.strptime(
            self.iso_path_reader.iso.apploader.buildDate, '%Y/%m/%d'
        )

        return header_info
