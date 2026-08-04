import logging
import re

from post_psx.npdrm.path_reader import NPDRMPathReader
from post_psx.processor import PostPsxIsoProcessor

LOGGER = logging.getLogger(__name__)


class PsVitaIsoProcessor(PostPsxIsoProcessor):
    # Nothing inside a vita package is an update folder
    update_folder = re.compile(r"(?!)")

    exe_patterns = [
        re.compile(r"^eboot\.bin$", re.IGNORECASE),
        re.compile(r".*\.suprx$", re.IGNORECASE),
        re.compile(r".*\.skprx$", re.IGNORECASE),
    ]

    # The app's own files sit inside a PFS container keyed by the license, so this
    # directory being present means the content is still encrypted after the pkg layer
    pfs_dir = "sce_pfs"

    @property
    def sfo_path(self):
        return "sce_sys/param.sfo"

    def get_disc_type(self):
        if isinstance(self.iso_path_reader, NPDRMPathReader):
            return {"disc_type": "hdd"}
        return {"disc_type": "card"}

    def get_exe_filename(self):
        try:
            self.iso_path_reader.get_file("eboot.bin")
            return "eboot.bin"
        except FileNotFoundError:
            return None

    @property
    def has_pfs_content(self):
        try:
            self.iso_path_reader.get_file(self.pfs_dir)
            return True
        except FileNotFoundError:
            return False

    def get_extra_fields(self):
        fields = {}
        try:
            params = self.parse_param_sfo()
            fields = {
                "sfo_category": params.get("CATEGORY"),
                "sfo_disc_id": params.get("TITLE_ID"),
                "sfo_disc_version": params.get("APP_VER"),
                "sfo_parental_level": params.get("PARENTAL_LEVEL"),
                "sfo_psp_system_version": params.get("PSP2_DISP_VER"),
                "sfo_title": params.get("TITLE"),
            }
        except FileNotFoundError:
            LOGGER.warning("No param.sfo found.")

        if self.has_pfs_content:
            # We decrypt the pkg but not the PFS layer, so the files we hashed are the
            # encrypted ones. Saying anything else would overstate what we did
            LOGGER.warning("PFS content is not supported, %s will not be fully decrypted", self.filename)
            fields["decryption_status"] = "encrypted"
        else:
            fields["decryption_status"] = getattr(self.iso_path_reader, "decryption_status", None)

        return fields
