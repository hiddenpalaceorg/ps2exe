import logging

from common.processor import BaseIsoProcessor

LOGGER = logging.getLogger(__name__)

class P3doIsoProcessor(BaseIsoProcessor):
    def get_disc_type(self):
        return {"disc_type": "cdr"}

    def get_exe_filename(self):
        return "/launchme"

    def get_most_recent_file_info(self, exe_date):
        return {}