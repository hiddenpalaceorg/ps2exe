import os
import struct
from typing import Optional

import xor_cipher

from .kirk_engine import KirkEngine, KirkError, KIRK


class KeyVault:
    # AMCTRL keys
    amHashKey1 = [0x9C, 0x48, 0xB6, 0x28, 0x40, 0xE6, 0x53, 0x3F, 0x05, 0x11, 0x3A, 0x4E, 0x65, 0xE6, 0x3A, 0x64]
    amHashKey2 = [0x70, 0xB4, 0x7B, 0xC0, 0xA1, 0x4B, 0xDA, 0xD6, 0xE0, 0x10, 0x14, 0xED, 0x72, 0x7C, 0x53, 0x4C]
    amHashKey3 = [0xE3, 0x50, 0xED, 0x1D, 0x91, 0x0A, 0x1F, 0xD0, 0x29, 0xBB, 0x1C, 0x3E, 0xF3, 0x40, 0x77, 0xFB]
    amHashKey4 = [0x13, 0x5F, 0xA4, 0x7C, 0xAB, 0x39, 0x5B, 0xA4, 0x76, 0xB8, 0xCC, 0xA9, 0x8F, 0x3A, 0x04, 0x45]
    amHashKey5 = [0x67, 0x8D, 0x7F, 0xA3, 0x2A, 0x9C, 0xA0, 0xD1, 0x50, 0x8A, 0xD8, 0x38, 0x5E, 0x4B, 0x01, 0x7E]


class BBMacError(Exception):
    """Base exception for BBMac errors"""
    pass


class BBCipherError(Exception):
    """Base exception for BBCipher errors"""
    pass


class BBMac:
    """
    BBMac - A PyCryptodome style interface for PSP BBMac algorithm

    Usage:
        # Create a new MAC object
        mac = BBMac.new(mode=0x1)

        # Update with data
        mac.update(data1)
        mac.update(data2)

        # Finalize and get the digest
        digest = mac.digest()

        # Or verify against a known digest
        is_valid = mac.verify(known_digest)

        # Extract key from MAC
        key = mac.extract_key(mac_value)
    """

    @classmethod
    def new(cls, mode: int = 0x1, key: bytes = None):
        """Create a new BBMac object with the given mode"""
        return cls(mode, key)

    def __init__(self, mode: int = 0x1, key: bytes = None):
        self.mode = mode
        self.key = bytearray(16) if key is None else bytearray(key[:16])
        self.pad = bytearray(16)
        self.pad_size = 0
        self.kirk = KirkEngine()

    def _scramble_bb(self, buf: bytearray, size: int, seed: int, cbc: int, kirk_code: int) -> Optional[bytearray]:
        """Set up and execute a KIRK operation on the buffer."""
        header = [
            # Set CBC mode
            cbc,
            # Set unknown parameters to 0
            0,
            0,
            # Set the key seed
            seed,
            # Set the data size
            size,
        ]

        # Pack the header back to buf
        buf[:20] = struct.pack("<5I", *header)

        try:
            return self.kirk.sceUtilsBufferCopyWithRange(size, buf, len(buf), kirk_code)[20:]
        except KirkError as e:
            # Handle KIRK errors - in this case we'll just print a warning
            print(f"KIRK error during scramble_bb: {e}")

    def update(self, data: bytes) -> 'BBMac':
        """Update the MAC with data"""
        if self.pad_size > 0x10 or len(data) < 0:
            raise BBMacError("Invalid key or data length")

        if (self.pad_size + len(data)) <= 0x10:
            # The key hasn't been set yet
            # Extract the hash from the data and set it as the key
            self.pad[self.pad_size:self.pad_size + len(data)] = data[:len(data)]
            self.pad_size += len(data)
        else:
            # Calculate the seed
            seed = 0x3A if self.mode == 0x2 else 0x38

            # Setup the buffer
            scramble_buf = bytearray(0x800 + 0x14)

            # Copy the previous pad key to the buffer
            scramble_buf[0x14:0x14 + self.pad_size] = self.pad[:self.pad_size]

            # Calculate new key length
            k_len = (self.pad_size + len(data)) & 0x0F
            k_len = 0x10 if k_len == 0 else k_len

            # Calculate new data length
            n_len = self.pad_size
            self.pad_size = k_len

            # Copy data's footer to make a new key
            remaining = len(data) - k_len
            self.pad[:k_len] = data[remaining:remaining + k_len]

            # Process the encryption in 0x800 blocks
            block_size = 0x800
            pos = 0

            while pos < remaining:
                current_block_size = min(block_size, remaining - pos)

                scramble_buf[0x14:0x14 + current_block_size] = data[pos:pos + current_block_size]

                # XOR with key and encrypt
                scramble_buf[0x14:0x24] = xor_cipher.cyclic_xor(bytes(scramble_buf[0x14:0x24]), bytes(self.key))

                result = self._scramble_bb(scramble_buf, current_block_size, seed, 0x4, KIRK.PSP_KIRK_CMD_ENCRYPT)
                self.key[:] = result[-16:]

                # Move to next block
                pos += current_block_size

        return self

    def digest(self, external_key: bytes = None) -> bytes:
        """Finalize and return the MAC digest"""
        if self.pad_size > 0x10:
            raise BBMacError("Invalid key length")

        # Calculate the seed
        seed = 0x3A if self.mode == 0x2 else 0x38

        # Set up the buffer
        scramble_buf = bytearray(0x800 + 0x14)

        # Set up necessary buffers
        key_buf = bytearray(0x10)
        result_buf = bytearray(0x10)

        # Encrypt the buffer with KIRK CMD 4
        key_buf = self._scramble_bb(scramble_buf, 0x10, seed, 0x4, KIRK.PSP_KIRK_CMD_ENCRYPT)

        # Apply custom padding management to the stored key
        b = 0x87 if (key_buf[0] & 0x80) else 0

        # Shift bytes left by 1 bit
        for i in range(15):
            key_buf[i] = ((key_buf[i] << 1) | (key_buf[i + 1] >> 7)) & 0xFF
        key_buf[15] = ((key_buf[15] << 1) ^ b) & 0xFF

        if self.pad_size < 0x10:
            # Do another round of shifting
            b = 0x87 if (key_buf[0] & 0x80) else 0
            for i in range(15):
                key_buf[i] = ((key_buf[i] << 1) | (key_buf[i + 1] >> 7)) & 0xFF
            key_buf[15] = ((key_buf[15] << 1) ^ b) & 0xFF

            # Add padding
            self.pad[self.pad_size] = 0x80
            if (self.pad_size + 1) < 0x10:
                self.pad[self.pad_size + 1:0x10] = bytes(0x10 - self.pad_size - 1)

        # XOR previous pad key with new one
        self.pad = scramble_buf[0x14:0x24] = xor_cipher.cyclic_xor(bytes(self.pad), bytes(key_buf))

        # Save the previous result key
        result_buf[:] = self.key[:]

        # XOR the decrypted key with the result key
        scramble_buf[0x14:0x24] = xor_cipher.cyclic_xor(bytes(scramble_buf[0x14:0x24]), bytes(result_buf))

        # Encrypt the key with KIRK CMD 4
        result_buf = self._scramble_bb(scramble_buf, 0x10, seed, 0x4, KIRK.PSP_KIRK_CMD_ENCRYPT)

        # XOR with amHashKey3
        result_buf[:0x10] = xor_cipher.cyclic_xor(bytes(result_buf[:0x10]), bytes(KeyVault.amHashKey3))

        # If mode is 2, encrypt again with KIRK CMD 5 and then KIRK CMD 4
        if self.mode == 0x2:
            # Copy the result buffer into the data buffer
            scramble_buf[0x14:0x24] = result_buf[:]

            # Encrypt with KIRK CMD 5 (seed is always 0x100)
            result_buf = self._scramble_bb(scramble_buf, 0x10, 0x100, 0x4, KIRK.PSP_KIRK_CMD_ENCRYPT_FUSE)
            scramble_buf[0x14:0x24] = result_buf[:]

            # Encrypt again with KIRK CMD 4
            result_buf = self._scramble_bb(scramble_buf, 0x10, seed, 0x4, KIRK.PSP_KIRK_CMD_ENCRYPT)

        # XOR with the supplied key and encrypt with KIRK CMD 4
        if external_key is not None:
            # XOR result buffer with user key
            result_buf[:0x10] = xor_cipher.cyclic_xor(bytes(result_buf[:0x10]), bytes(external_key))

            # Copy the result buffer into the data buffer
            scramble_buf[0x14:0x24] = result_buf[:]

            # Encrypt with KIRK CMD 4
            result_buf = self._scramble_bb(scramble_buf, 0x10, seed, 0x4, KIRK.PSP_KIRK_CMD_ENCRYPT)

        self.mode = 0
        self.pad_size = 0
        self.pad = bytearray(16)
        self.key = bytearray(16)

        return bytes(result_buf)

    def verify(self, mac_value: bytes, external_key: bytes = None) -> bool:
        """Verify a MAC value against the current state"""
        # Save the current mode since digest() will reset it
        saved_mode = self.mode

        # Generate our MAC
        our_mac = self.digest(external_key)

        # If mode is 3, decrypt the mac_value first
        if (saved_mode & 0x3) == 0x3:
            mac_to_verify = self.decrypt_mac_key(mac_value, 0x63)
        else:
            mac_to_verify = mac_value

        # Compare the MACs
        return our_mac == mac_to_verify

    def decrypt_mac_key(self, key: bytes, seed: int) -> bytes:
        """Decrypt a BBMac key"""
        scramble_buf = bytearray(0x10 + 0x14)
        scramble_buf[0x14:0x24] = key[:0x10]
        dec_key = self._scramble_bb(scramble_buf, 0x10, seed, 0x5, KIRK.PSP_KIRK_CMD_DECRYPT)

        return bytes(dec_key) if dec_key else bytes(16)

    def extract_key(self, mac_value: bytes) -> bytes:
        """Extract a key from a BBMac and its context"""
        # Save the mode as it will be reset by digest()
        saved_mode = self.mode

        # Generate MAC key
        mac_key = self.digest()

        # Get decrypted MAC value
        if (saved_mode & 0x3) == 0x3:
            dec_key = self.decrypt_mac_key(mac_value, 0x63)
        else:
            dec_key = mac_value[:0x10]

        # Decrypt the key with the mode seed
        seed = 0x3A if saved_mode == 0x2 else 0x38
        final_key = self.decrypt_mac_key(dec_key, seed)

        # XOR to get the final key
        key = xor_cipher.cyclic_xor(bytes(mac_key), bytes(final_key))

        return bytes(key)


class BBCipher:
    """
    BBCipher - A PyCryptodome style interface for PSP BBCipher algorithm

    Usage:
        # For encryption:
        cipher = BBCipher.new(mode=BBCipher.MODE_ENCRYPT, key=key)
        ciphertext = cipher.update(plaintext)

        # For decryption:
        cipher = BBCipher.new(mode=BBCipher.MODE_DECRYPT, key=key, seed=seed)
        plaintext = cipher.update(ciphertext)
    """

    # Constants for gen_mode
    MODE_ENCRYPT = 0x1
    MODE_DECRYPT = 0x2

    @classmethod
    def new(cls, enc_mode: int, gen_mode: int, key: bytes = None, seed: int = 0):
        """Create a new BBCipher object"""
        return cls(enc_mode, gen_mode, key, seed)

    def __init__(self, enc_mode: int, gen_mode: int, key: bytes = None, seed: int = 0):
        self.enc_mode = enc_mode
        self.gen_mode = gen_mode
        self.seed = seed
        self.key = key if key is not None else bytes(16)
        self.buf = bytearray(16)
        self.current_seed = 0
        self.kirk = KirkEngine()

        # Initialize the cipher
        self._init_cipher()

    def _init_cipher(self):
        """Initialize the cipher context"""
        data = bytearray(16)

        # Key generator mode 0x1 (encryption): use an encrypted pseudo random number
        if self.gen_mode == self.MODE_ENCRYPT:
            self.current_seed = 0x1

            # Generate SHA-1 to act as seed for encryption
            try:
                rseed = self.kirk.kirk_CMD14(0x14)
            except KirkError:
                # Fallback to os.urandom if KIRK fails
                rseed = os.urandom(0x14)

            # Prepare header with seed
            header = bytearray(0x24)
            header[:0x14] = rseed
            header[0x14:0x24] = rseed[:0x10]
            header[0x20:0x24] = bytes(4)  # Zero out last 4 bytes

            if self.enc_mode == 0x2:
                # Encryption mode 0x2: XOR with AMCTRL keys, encrypt with KIRK CMD5 and XOR with the given key
                for i in range(0x10):
                    header[0x14 + i] ^= KeyVault.amHashKey4[i]
                header = self._scramble_bb(header, 0x10, self.seed, 0x4, KIRK.PSP_KIRK_CMD_ENCRYPT)
                self.buf[:0x10] = header

                # If the key is not null, XOR the hash with it
                if self.key and any(k != 0 for k in self.key):
                    for i in range(0x10):
                        self.buf[i] ^= self.key[i]
            else:
                # Encryption mode 0x1: XOR with AMCTRL keys, encrypt with KIRK CMD4 and XOR with the given key
                for i in range(0x10):
                    header[0x14 + i] ^= KeyVault.amHashKey4[i]

                header = self._scramble_bb(header, 0x10, self.seed, 0x5, KIRK.PSP_KIRK_CMD_DECRYPT)

                self.buf[:0x10] = header

                # If the key is not null, XOR the hash with it
                if self.key and any(k != 0 for k in self.key):
                    for i in range(0x10):
                        self.buf[i] ^= self.key[i]

        # Key generator mode 0x2 (decryption): directly XOR the data with the given key
        elif self.gen_mode == self.MODE_DECRYPT:
            self.current_seed = self.seed
            # The data hash (first 16-bytes) will be set during the first update

        return data

    def update(self, data: bytes) -> bytes:
        """Update cipher with data"""
        if not data:
            return b''

        if len(data) % 16 != 0:
            raise BBCipherError("Data length must be a multiple of 16")

        # Make a copy of the data that we can modify
        data_buffer = bytearray(data)

        # For decryption mode, grab the data hash from the first block
        if self.gen_mode == self.MODE_DECRYPT and self.current_seed == self.seed:
            self.buf[:0x10] = data[:0x10]
            # If the key is not null, XOR the hash with it
            if self.key and any(k != 0 for k in self.key):
                for i in range(0x10):
                    self.buf[i] ^= self.key[i]

        # Process the data in 0x800 blocks for efficiency
        result = bytearray()
        for offset in range(0, len(data), 0x800):
            # Get the length to process (0x800 or remaining)
            process_len = min(0x800, len(data) - offset)
            if process_len < 0x10:  # Skip if less than a block
                continue

            # Process this chunk
            processed = self._cipher_member(
                data_buffer,
                offset,
                process_len
            )
            result.extend(processed)

        return bytes(result)

    def _cipher_member(self, data: bytearray, data_offset: int, length: int) -> bytearray:
        """Cipher operation for BBCipher context"""
        data_buf = bytearray(length + 0x14)
        key_buf1 = bytearray(0x10)
        key_buf2 = bytearray(0x10)
        hash_buf = bytearray(0x10)

        # Copy the hash stored by init
        data_buf[0x14:0x24] = self.buf

        if self.enc_mode == 0x2:
            # Decryption mode 0x02: XOR the hash with AMCTRL keys and decrypt with KIRK CMD8
            for i in range(0x10):
                data_buf[0x14 + i] ^= KeyVault.amHashKey5[i]

            data_buf = self._scramble_bb(data_buf, 0x10, 0x100, 0x5, KIRK.PSP_KIRK_CMD_DECRYPT_FUSE)
        else:
            # Decryption mode 0x01: XOR the hash with AMCTRL keys and decrypt with KIRK CMD7
            for i in range(0x10):
                data_buf[0x14 + i] ^= KeyVault.amHashKey5[i]

            result = self._scramble_bb(data_buf, 0x10, 0x39, 0x5, KIRK.PSP_KIRK_CMD_DECRYPT)

            for i in range(0x10):
                data_buf[i] = result[i] ^ KeyVault.amHashKey4[i]

        # Store the calculated key
        key_buf2[:] = data_buf[:0x10]

        # Apply extra padding if seed is not 1
        if self.current_seed > 0x1:
            key_buf1[:0xC] = key_buf2[:0xC]
            struct.pack_into("<I", key_buf1, 0xC, self.current_seed - 1)

        # Generate key stream
        for i in range(0x14, length + 0x14, 0x10):
            # Copy key components
            data_buf[i:i + 0xC] = key_buf2[:0xC]
            struct.pack_into("<I", data_buf, i + 0xC, self.current_seed)
            self.current_seed += 1

        # Copy the generated hash to hash_buf
        hash_buf[:] = data_buf[length + 0x04:length + 0x14]

        # Decrypt the hash with KIRK CMD7 and seed 0x63
        data_buf = self._scramble_bb(data_buf, length, 0x63, 0x5, KIRK.PSP_KIRK_CMD_DECRYPT)

        # XOR the first 16-bytes of data with the saved key to generate a new hash
        data_buf[:0x10] = xor_cipher.cyclic_xor(bytes(data_buf[:0x10]), bytes(key_buf1))

        # Copy back the last hash from the list to the first keyBuf
        key_buf1[:] = hash_buf[:]

        # Finally, XOR the data with the processed buffer and return
        return bytearray(xor_cipher.cyclic_xor(bytes(data[data_offset:data_offset + length]), bytes(data_buf)))

    def _scramble_bb(self, buf: bytearray, size: int, seed: int, cbc: int, kirk_code: int) -> Optional[bytearray]:
        """Set up and execute a KIRK operation on the buffer."""
        header = [
            # Set CBC mode
            cbc,
            # Set unknown parameters to 0
            0,
            0,
            # Set the key seed
            seed,
            # Set the data size
            size,
        ]

        # Pack the header back to buf
        buf[:20] = struct.pack("<5I", *header)

        try:
            return self.kirk.sceUtilsBufferCopyWithRange(size, buf, len(buf), kirk_code)[20:]
        except KirkError as e:
            # Handle KIRK errors - in this case we'll just print a warning
            print(f"KIRK error during scramble_bb: {e}")

    def finalize(self) -> None:
        """Clean up cipher resources"""
        self.enc_mode = 0
        self.current_seed = 0
        self.buf = bytearray(16)
