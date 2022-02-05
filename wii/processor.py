import hashlib

from gamecube.processor import GamecubeIsoProcessor


class WiiIsoProcessor(GamecubeIsoProcessor):
    SDK_STRING = b"RVL_SDK"

    def get_disc_type(self):
        if self.iso_path_reader.iso.disc.disable_encryption:
            return {"disc_type": "rvth"}
        if self.iso_path_reader.iso.partition.master_key in [None, "rvt-debug"]:
            return {"disc_type": "rvtr"}
        return {"disc_type": "dvdr"}

    def get_extra_fields(self):
        fields = super().get_extra_fields()
        h3_hash_together = hashlib.md5()
        h3_hashes_sorted = sorted(self.iso_path_reader.iso.partition.h3_hashes)
        h3_hash_together.update(b''.join(h3_hashes_sorted))
        fields["alt_all_files_hash"] = h3_hash_together.hexdigest()

        return fields
