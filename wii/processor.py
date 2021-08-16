from gamecube.processor import GamecubeIsoProcessor

class WiiIsoProcessor(GamecubeIsoProcessor):
    SDK_STRING = b"RVL_SDK"

    def get_disc_type(self):
        if self.iso_path_reader.iso.partition.master_key in [None, "rvt-debug"]:
            return {"disc_type": "rvtr"}
        return {"disc_type": "dvdr"}