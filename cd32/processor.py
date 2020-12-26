import logging

from common.processor import BaseIsoProcessor

LOGGER = logging.getLogger(__name__)

class CD32IsoProcessor(BaseIsoProcessor):
    def get_disc_type(self):
        return {"disc_type": "cdr"}

    def get_exe_filename(self):
    # Note: This isn't the actual executable. The executable itself needs to be interpreted from the Startup-Sequence file. It'll most likely be the last file referenced from the bottom.
        for dir in ["/S", "/s"]:
            try:
                for file in self.iso_path_reader.iso_iterator(self.iso_path_reader.get_file(dir)):
                    file_path = self.iso_path_reader.get_file_path(file)
                    if file_path.lower() == "/s/startup-sequence":
                        return file_path
            except FileNotFoundError:
                pass