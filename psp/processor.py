import fnmatch
import logging
import pathlib
import re

from post_psx.npdrm.path_reader import NPDRMPathReader
from post_psx.processor import PostPsxIsoProcessor
from utils.files import ConcatenatedFile, BinWrapper

LOGGER = logging.getLogger(__name__)


class PspIsoProcessor(PostPsxIsoProcessor):

    update_folder = re.compile(".*/PSP_GAME/SYSDIR/UPDATE/$", re.IGNORECASE)

    def __init__(self, iso_path_reader, iso_filename, system, progress_manager):
        if isinstance(iso_path_reader, NPDRMPathReader):
            self.disc_type = "hdd"
        else:
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

        self.base_dir = ""
        for file in iso_path_reader.iso_iterator(iso_path_reader.get_root_dir(), include_dirs=True):
            if iso_path_reader.is_directory(file):
                if iso_path_reader.get_file_path(file).strip("/") == "PSP_GAME":
                    self.base_dir = "/PSP_GAME"
                    break

        super().__init__(iso_path_reader, iso_filename, system, progress_manager)

    @property
    def sfo_path(self):
        return f"{self.base_dir}/PARAM.SFO"

    def get_disc_type(self):
        return {"disc_type": self.disc_type}

    def get_exe_filename(self):
        try:
            self.iso_path_reader.get_file(f"{self.base_dir}/SYSDIR/EBOOT.BIN")
            return f"{self.base_dir}/SYSDIR/EBOOT.BIN"
        except FileNotFoundError:
            return None

    def get_extra_fields(self):
        try:
            self.iso_path_reader.get_file(f"{self.base_dir}/SYSDIR/BOOT.BIN")
            self.get_exe_filename = lambda: f"{self.base_dir}/SYSDIR/BOOT.BIN"
            alt_exe_hash = super().hash_exe()
        except FileNotFoundError:
            alt_exe_hash = {}

        try:
            params = self.parse_param_sfo()
        except FileNotFoundError:
            params = {}

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
            "decryption_status": getattr(self.iso_path_reader, "decryption_status", None),

        }

