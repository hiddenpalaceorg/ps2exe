import logging

from common.processor import BaseIsoProcessor

LOGGER = logging.getLogger(__name__)

class P3doIsoProcessor(BaseIsoProcessor):
    def get_disc_type(self):
        return {"disc_type": "cdr"}

    def get_exe_filename(self):
        try:
            dir = self.iso_path_reader.get_root_dir()
            for file in self.iso_path_reader.iso_iterator(dir):
                file_path = self.iso_path_reader.get_file_path(file)
                if file_path.lower() == "/launchme":
                    return file_path
        except FileNotFoundError:
            pass

    def get_most_recent_file_info(self, exe_date):
        return {}