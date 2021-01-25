import logging
import mmap
from os.path import basename

from common.processor import BaseIsoProcessor
from utils.files import ConcatenatedFile

LOGGER = logging.getLogger(__name__)


class DreamcastIsoProcessor(BaseIsoProcessor):
    def __init__(self, iso_path_reader, iso_filename, *args):
        file_name = basename(iso_filename)
        super().__init__(iso_path_reader, iso_filename, *args)


