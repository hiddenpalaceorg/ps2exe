import logging

from common.processor import BaseIsoProcessor

LOGGER = logging.getLogger(__name__)

class CdiIsoProcessor(BaseIsoProcessor):

    def get_exe_filename(self):
        app_id = getattr(self.iso_path_reader.get_pvd(), "application_identifier", None)
        if hasattr(app_id, "record"):
            return app_id.record().decode()
        return app_id.decode()