import fnmatch
import logging
import pathlib
import re

from post_psx.processor import PostPsxIsoProcessor
from utils.files import ConcatenatedFile, BinWrapper

LOGGER = logging.getLogger(__name__)


class PspIsoProcessor(PostPsxIsoProcessor):

    update_folder = re.compile(".*/PSP_GAME/SYSDIR/UPDATE/$", re.IGNORECASE)
    sfo_path = "/PSP_GAME/PARAM.SFO"

    def __init__(self, iso_path_reader, iso_filename, system, progress_manager):
        self.disc_type = "umd"
        parent_container = iso_path_reader.parent_container
        iso_dir = parent_container.get_file(str(pathlib.Path(iso_filename).parent))
        rule = re.compile(fnmatch.translate("*USER_L*.IMG"), re.IGNORECASE)
        sub_imgs = [
            parent_container.get_file_path(file)
            for file in parent_container.iso_iterator(iso_dir)
            if rule.match(parent_container.get_file_path(file))
        ]

        if len(sub_imgs) > 1:
            self.disc_type = "dvdr"

            offsets = [0]
            sub_imgs = sorted(sub_imgs)
            files = []
            for sub_img in sub_imgs:
                file = parent_container.get_file(sub_img)
                offsets.append(parent_container.get_file_size(file))
                f = parent_container.open_file(file)
                if hasattr(f, "__enter__"):
                    f.__enter__()
                files.append(
                    BinWrapper(
                        f,
                        sector_size=2048,
                        sector_offset=0,
                        virtual_sector_size=2048
                    )
                )
            offsets.pop()

            fp = ConcatenatedFile(files, offsets)

            from common.factory import IsoProcessorFactory
            iso_path_reader = IsoProcessorFactory.get_iso_path_readers(
                fp, iso_filename, iso_path_reader.parent_container, progress_manager
            )[0][0]

        super().__init__(iso_path_reader, iso_filename, system, progress_manager)

    def get_disc_type(self):
        return {"disc_type": self.disc_type}

    def get_exe_filename(self):
        return "/PSP_GAME/SYSDIR/EBOOT.BIN"

    def get_extra_fields(self):
        self.get_exe_filename = lambda: "/PSP_GAME/SYSDIR/BOOT.BIN"
        alt_exe_hash = super().hash_exe()
        params = self.parse_param_sfo()

        return {
            "sfo_category": params.get("CATEGORY"),
            "sfo_disc_id": params.get("DISC_ID"),
            "sfo_disc_version": params.get("DISC_VERSION"),
            "sfo_parental_level": params.get("PARENTAL_LEVEL"),
            "sfo_psp_system_version": params.get("PSP_SYSTEM_VER"),
            "sfo_title": params.get("TITLE"),
            "alt_exe_filename": alt_exe_hash.get("exe_filename"),
            "alt_exe_date": alt_exe_hash.get("exe_date"),
            "alt_md5": alt_exe_hash.get("md5"),
        }

