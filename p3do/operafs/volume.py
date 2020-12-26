import struct


class Volume:
    SIZE = 83

    SYNCBYTECOUNT = 5
    VOLUMEINFOCOUNT = 32

    FMT = f">{SYNCBYTECOUNT}sbb{VOLUMEINFOCOUNT}s{VOLUMEINFOCOUNT}sIII"

    '''
            return {
                "system_identifier": disclabel.system_id.decode(),
                "volume_identifier": disclabel.volume_id.decode(),
                "volume_set_identifier": disclabel.album_id.decode(),
                "volume_creation_date": disclabel.creation_date,
                "volume_modification_date": disclabel.mod_date,
                "volume_expiration_date": disclabel.exp_date,
                "volume_effective_date": disclabel.effective_date,
            }'''

    def __init__(self, data):
        self.sync_bytes, self.record_version, self.flags, \
        comment, label, self.id, self.block_size, \
        self.block_count = struct.unpack(self.FMT, data)
        self.volume_identifier = comment.rstrip(b"\x00").decode()
        self.system_identifier = label.rstrip(b"\x00").decode()
