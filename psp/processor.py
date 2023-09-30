import logging
import mmap
import re
from os.path import basename

from post_psx.processor import PostPsxIsoProcessor
from utils.files import ConcatenatedFile

LOGGER = logging.getLogger(__name__)


class PspIsoProcessor(PostPsxIsoProcessor):

    update_folder = re.compile(".*/PSP_GAME/SYSDIR/UPDATE/$", re.IGNORECASE)
    sfo_path = "/PSP_GAME/PARAM.SFO"

    def __init__(self, iso_path_reader, *args):
        sub_imgs = {}
        self.disc_type = "umd"
        for file in iso_path_reader.iso_iterator(iso_path_reader.get_root_dir(), recursive=False):
            file_basename = basename(iso_path_reader.get_file_path(file))
            if file_basename.startswith("USER_L") and file_basename.endswith(".IMG"):
                with iso_path_reader.open_file(file) as fp:
                    buf = mmap.mmap(-1, fp.length())
                    fp.readinto(buf)
                    sub_imgs[file_basename] = buf

        if sub_imgs:
            self.disc_type = "dvdr"

            offsets = [0]
            sub_imgs = sorted(sub_imgs.items())
            files = []
            for _, sub_img in sub_imgs:
                offsets.append(len(sub_img))
                files.append(sub_img)
            offsets.pop()

            fp = ConcatenatedFile(files, offsets)

            from common.factory import IsoProcessorFactory
            iso_path_reader = IsoProcessorFactory.get_iso_path_reader(fp, b'')

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
            "alt_exe_filename": alt_exe_hash.get("exe_filename"),
            "alt_exe_date": alt_exe_hash.get("exe_date"),
            "alt_md5": alt_exe_hash.get("md5"),
        }

