import logging

from post_psx.processor import PostPsxIsoProcessor

LOGGER = logging.getLogger(__name__)


class Ps3IsoProcessor(PostPsxIsoProcessor):
    update_folder = "/PS3_UPDATE/"
    sfo_path = "/PS3_GAME/PARAM.SFO"

    def get_disc_type(self):
        return {"disc_type": "dvd-r"}

    def get_exe_filename(self):
        return "/PS3_GAME/USRDIR/EBOOT.BIN"

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

