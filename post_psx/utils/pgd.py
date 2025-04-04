from post_psx.types import PGDHeader, PGDSubHeader
from post_psx.utils.kirk.bb import BBMac, BBCipher


class PGDFile:
    dnas_key_1 = bytes(
        [0xED, 0xE2, 0x5D, 0x2D, 0xBB, 0xF8, 0x12, 0xE5, 0x3C, 0x5C, 0x59, 0x32, 0xFA, 0xE3, 0xE2, 0x43])
    dnas_key_2 = bytes(
        [0x27, 0x74, 0xFB, 0xEB, 0xA4, 0xA0, 0x01, 0xD7, 0x02, 0x56, 0x9E, 0x33, 0x8C, 0x19, 0x57, 0x83])

    # PGD_SIZE = 0xB6600
    fp = None

    def decrypt_pgd(self, pgd_offset):
        self.fp.seek(pgd_offset)
        pgd_header_raw = bytearray(self.fp.read(PGDHeader.struct.size + PGDSubHeader.struct.size))
        pgd_header = PGDHeader.unpack(pgd_header_raw[0:PGDHeader.struct.size])
        pgd_subheader = PGDSubHeader.unpack(pgd_header_raw[0x30:])
        if not pgd_header.check_magic():
            return False

        # Get the fixed DNAS key
        fkey = None
        if pgd_header.open_flag & 0x2 == 0x2:
            fkey = self.dnas_key_1
        elif pgd_header.open_flag & 0x1 == 0x1:
            fkey = self.dnas_key_2

        if fkey is None:
            print(f"PGD: Invalid DNAS flag! {pgd_header.open_flag:08x}")
            return False

        # Test MAC hash at 0x80 (DNAS hash)
        bbmac = BBMac.new(pgd_header.mac_type, bytearray(16))
        bbmac.update(pgd_header_raw[:0x80])
        result = bbmac.verify(pgd_subheader.encrypted_ioctl_hash, fkey)

        if not result:
            print("PGD: Invalid 0x80 MAC hash!")
            return False

        # Test MAC hash at 0x70 (key hash)
        bbmac = BBMac.new(pgd_header.mac_type, bytearray(16))
        bbmac.update(pgd_header_raw[:0x70])

        # Generate the key from MAC 0x70
        header_key = bbmac.extract_key(pgd_subheader.ioctl_hash)

        # Now we can decrypt the PGD header using the vkey
        cipher = BBCipher.new(pgd_header.cipher_type, BBCipher.MODE_DECRYPT, header_key, 0)
        cipher.update(pgd_header.key)
        pgd_subheader.set_decrypted_header(cipher.update(pgd_header_raw[0x30:0x60]))

        # Test MAC hash at 0x60 (table hash)
        self.fp.seek(pgd_offset + pgd_subheader.table_offset)
        table_data = self.fp.read(pgd_subheader.block_nr * 16)
        bbmac = BBMac.new(pgd_header.mac_type, bytearray(16))
        bbmac.update(table_data)
        result = bbmac.verify(pgd_subheader.file_hash, header_key)

        if not result:
            print("PGD: Invalid 0x60 MAC hash!")
            return False

        # Finally, decrypt the actual data using the vkey
        self.fp.seek(pgd_offset + 0x90)
        encrypted_data = self.fp.read(pgd_subheader.align_size)
        cipher = BBCipher.new(pgd_header.cipher_type, BBCipher.MODE_DECRYPT, header_key, 0)
        cipher.update(pgd_subheader.hash_key)
        return cipher.update(encrypted_data)
