import logging
from os.path import basename

from post_psx.processor import PostPsxIsoProcessor
from psp.chained_subimg_reader import ChainedSubImgReader

LOGGER = logging.getLogger(__name__)


class PspIsoProcessor(PostPsxIsoProcessor):
    update_folder = "/PSP_GAME/SYSDIR/UPDATE/"
    sfo_path = "/PSP_GAME/PARAM.SFO"

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
            iso_path_reader = IsoProcessorFactory.get_iso_path_reader(fp, '')

        super().__init__(iso_path_reader, *args)

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
            "alt_exe_filename": alt_exe_hash["exe_filename"],
            "alt_exe_date": alt_exe_hash["exe_date"],
            "alt_md5": alt_exe_hash["md5"],
        }

