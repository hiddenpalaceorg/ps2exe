import logging
import struct
from typing import Optional

import xor_cipher

from post_psx.types import KirkAES128CBCHeader
from .kirk_engine import KirkCommand, KirkEngine, KirkMode

LOGGER = logging.getLogger(__name__)

KIRK_HEADER_SIZE = KirkAES128CBCHeader.struct.size  # 0x14
BLOCK_SIZE = 0x10
# AMCTRL works the KIRK engine 0x800 bytes at a time
CHUNK_SIZE = 0x800

# Fixed keys AMCTRL folds into its MAC and keystream. Numbered 3/4/5 because two more
# exist in the wider PSP key set, neither of which any MAC or cipher path here touches.
AMCTRL_HASHKEY_3 = bytes.fromhex("e350ed1d910a1fd029bb1c3ef34077fb")
AMCTRL_HASHKEY_4 = bytes.fromhex("135fa47cab395ba476b8cca98f3a0445")
AMCTRL_HASHKEY_5 = bytes.fromhex("678d7fa32a9ca0d1508ad8385e4b017e")

# The key vault slots AMCTRL asks KIRK for
MAC_KEYSEED = 0x38
MAC_KEYSEED_PER_CONSOLE = 0x3A
MAC_KEYSEED_ENCRYPTED = 0x63
CIPHER_KEYSEED_HASH = 0x39
CIPHER_KEYSEED_KEYSTREAM = 0x63
# Key seed 0 with the submode byte set to 1, i.e. "use the per-console key" - the header
# packs the two as adjacent bytes, so the pair reads as 0x100. See KirkAES128CBCHeader
PER_CONSOLE_KEYSEED = 0x100


class BBMacError(Exception):
    """Base exception for BBMac errors"""


class BBCipherError(Exception):
    """Base exception for BBCipher errors"""


def _scramble(kirk: KirkEngine, buf: bytearray, size: int, keyseed: int,
              mode: KirkMode, command: KirkCommand) -> bytearray:
    """Run one AMCTRL KIRK operation over `buf`, returning just the payload.

    AMCTRL always hands KIRK a buffer whose first 0x14 bytes are the header to fill in and
    whose payload follows, and only ever wants the payload back. A KirkError propagates;
    PGDFile.decrypt_pgd turns it into a failed decrypt.
    """
    header = KirkAES128CBCHeader(mode=mode, keyseed=keyseed & 0xFF,
                                 submode=(keyseed >> 8) & 0xFF, data_size=size)
    buf[:KIRK_HEADER_SIZE] = header.pack()

    return kirk.sce_utils_buffer_copy_with_range(size, buf, len(buf), command)[KIRK_HEADER_SIZE:]


class BBMac:
    """PSP BBMac - AMCTRL's CMAC variant, in a PyCryptodome shaped interface.

    Usage:
        mac = BBMac.new(mode, key)
        mac.update(data)                    # may be called repeatedly
        digest = mac.digest()               # or .verify(known_mac) / .extract_key(mac_value)

    digest() consumes the object: it clears the mode, key and pad on the way out, which is
    why verify() and extract_key() snapshot the mode before calling it.

    Mode 2 chains through KIRK's per-console key, which cannot be derived without the
    console's fuse ID, so a mode 2 digest never matches a real console's.
    """

    MODE_PER_CONSOLE = 0x2
    # Modes with both low bits set carry their MAC encrypted under MAC_KEYSEED_ENCRYPTED
    MODE_ENCRYPTED_MAC = 0x3

    @classmethod
    def new(cls, mode: int = 0x1, key: Optional[bytes] = None) -> "BBMac":
        """Create a new BBMac object with the given mode"""
        return cls(mode, key)

    def __init__(self, mode: int = 0x1, key: Optional[bytes] = None):
        self.mode = mode
        self.key = bytearray(BLOCK_SIZE) if key is None else bytearray(key[:BLOCK_SIZE])
        self.pad = bytearray(BLOCK_SIZE)
        self.pad_size = 0
        self.kirk = KirkEngine()

    @property
    def _keyseed(self) -> int:
        """Which key vault slot this mode's blocks are encrypted with"""
        return MAC_KEYSEED_PER_CONSOLE if self.mode == self.MODE_PER_CONSOLE else MAC_KEYSEED

    def update(self, data: bytes) -> "BBMac":
        """Feed data into the MAC, holding back whatever doesn't fill a whole block"""
        if self.pad_size > BLOCK_SIZE:
            raise BBMacError(f"Pad holds {self.pad_size} bytes, past the {BLOCK_SIZE} byte block")

        if self.pad_size + len(data) <= BLOCK_SIZE:
            # Not enough for a block yet, so just accumulate
            self.pad[self.pad_size:self.pad_size + len(data)] = data
            self.pad_size += len(data)
            return self

        scramble_buf = bytearray(CHUNK_SIZE + KIRK_HEADER_SIZE)
        # Whatever the last call held back leads the first block
        carried = self.pad_size
        scramble_buf[KIRK_HEADER_SIZE:KIRK_HEADER_SIZE + carried] = self.pad[:carried]

        # Hold back the tail that won't fill a block, for the next call or for digest()
        self.pad_size = (carried + len(data)) & (BLOCK_SIZE - 1) or BLOCK_SIZE
        size = len(data) - self.pad_size
        self.pad[:self.pad_size] = data[size:size + self.pad_size]

        pos = 0
        # `or carried` matters when this call's data all goes into the pad while the previous
        # call's leftovers still owe a block. Guarding on new data alone would drop them
        while pos < size or carried:
            # `carried` bytes of the block are already in place, so the run of new data
            # that fills the rest of it is shorter by that much
            block_size = min(CHUNK_SIZE, size - pos + carried)
            taken = block_size - carried
            start = KIRK_HEADER_SIZE + carried
            scramble_buf[start:start + taken] = data[pos:pos + taken]

            # Chain the running key into the head of the block, then encrypt and keep the
            # last 16 bytes as the next running key. Feeding the previous block's final
            # ciphertext back in this way is what makes a split mid-stream come out the same
            # as one long block
            head = slice(KIRK_HEADER_SIZE, KIRK_HEADER_SIZE + BLOCK_SIZE)
            scramble_buf[head] = xor_cipher.cyclic_xor(bytes(scramble_buf[head]), bytes(self.key))
            encrypted = _scramble(self.kirk, scramble_buf, block_size, self._keyseed,
                                  KirkMode.ENCRYPT_CBC, KirkCommand.ENCRYPT_STATIC)
            self.key[:] = encrypted[-BLOCK_SIZE:]

            pos += taken
            carried = 0

        return self

    def digest(self, external_key: Optional[bytes] = None) -> bytes:
        """Finalize and return the 16 byte MAC"""
        if self.pad_size > BLOCK_SIZE:
            raise BBMacError(f"Pad holds {self.pad_size} bytes, past the {BLOCK_SIZE} byte block")

        keyseed = self._keyseed
        scramble_buf = bytearray(CHUNK_SIZE + KIRK_HEADER_SIZE)

        # The subkey the final block is folded into comes from encrypting a block of zeros
        subkey = self._double(_scramble(self.kirk, scramble_buf, BLOCK_SIZE, keyseed,
                                       KirkMode.ENCRYPT_CBC, KirkCommand.ENCRYPT_STATIC))
        if self.pad_size < BLOCK_SIZE:
            # A short final block takes the second subkey and CMAC's 0x80 terminator
            subkey = self._double(subkey)
            self.pad[self.pad_size] = 0x80
            self.pad[self.pad_size + 1:BLOCK_SIZE] = bytes(BLOCK_SIZE - self.pad_size - 1)

        # Fold the final block, its subkey and the running key together, then encrypt
        block = xor_cipher.cyclic_xor(bytes(self.pad), bytes(subkey))
        mac = self._encrypt_block(scramble_buf, xor_cipher.cyclic_xor(block, bytes(self.key)),
                                  keyseed, KirkCommand.ENCRYPT_STATIC)
        mac = xor_cipher.cyclic_xor(bytes(mac), AMCTRL_HASHKEY_3)

        if self.mode == self.MODE_PER_CONSOLE:
            # Chain out through the per-console key and back in through the vault key
            mac = self._encrypt_block(scramble_buf, mac, PER_CONSOLE_KEYSEED,
                                      KirkCommand.ENCRYPT_PERCONSOLE)
            mac = self._encrypt_block(scramble_buf, mac, keyseed, KirkCommand.ENCRYPT_STATIC)

        if external_key is not None:
            mac = self._encrypt_block(scramble_buf, xor_cipher.cyclic_xor(bytes(mac), bytes(external_key)),
                                      keyseed, KirkCommand.ENCRYPT_STATIC)

        self.mode = 0
        self.pad_size = 0
        self.pad = bytearray(BLOCK_SIZE)
        self.key = bytearray(BLOCK_SIZE)

        return bytes(mac)

    def verify(self, mac_value: bytes, external_key: Optional[bytes] = None) -> bool:
        """Check a stored MAC against the one this object computes"""
        # digest() resets the mode, so snapshot it first
        mode = self.mode
        our_mac = self.digest(external_key)

        if mode & 0x3 == self.MODE_ENCRYPTED_MAC:
            mac_value = self.decrypt_mac_key(mac_value, MAC_KEYSEED_ENCRYPTED)

        return our_mac == mac_value

    def decrypt_mac_key(self, key: bytes, keyseed: int) -> bytes:
        """Run a stored MAC key back through KIRK's decrypt direction"""
        scramble_buf = bytearray(BLOCK_SIZE + KIRK_HEADER_SIZE)
        scramble_buf[KIRK_HEADER_SIZE:] = key[:BLOCK_SIZE]

        return bytes(_scramble(self.kirk, scramble_buf, BLOCK_SIZE, keyseed,
                               KirkMode.DECRYPT_CBC, KirkCommand.DECRYPT_STATIC))

    def extract_key(self, mac_value: bytes) -> bytes:
        """Recover the key a stored MAC was built with"""
        # digest() resets the mode, so snapshot it first
        mode = self.mode
        mac_key = self.digest()

        if mode & 0x3 == self.MODE_ENCRYPTED_MAC:
            mac_value = self.decrypt_mac_key(mac_value, MAC_KEYSEED_ENCRYPTED)

        keyseed = MAC_KEYSEED_PER_CONSOLE if mode == self.MODE_PER_CONSOLE else MAC_KEYSEED
        final_key = self.decrypt_mac_key(mac_value[:BLOCK_SIZE], keyseed)

        return bytes(xor_cipher.cyclic_xor(bytes(mac_key), bytes(final_key)))

    def _encrypt_block(self, scramble_buf: bytearray, block: bytes,
                       keyseed: int, command: KirkCommand) -> bytearray:
        """Push one 16 byte block through KIRK, reusing the scramble buffer"""
        scramble_buf[KIRK_HEADER_SIZE:KIRK_HEADER_SIZE + BLOCK_SIZE] = block

        return _scramble(self.kirk, scramble_buf, BLOCK_SIZE, keyseed,
                         KirkMode.ENCRYPT_CBC, command)

    @staticmethod
    def _double(subkey: bytes) -> bytes:
        """Double a subkey in GF(2**128), the usual CMAC left shift"""
        doubled = int.from_bytes(subkey[:BLOCK_SIZE], "big") << 1
        if subkey[0] & 0x80:
            doubled ^= 0x87

        return (doubled & (1 << 128) - 1).to_bytes(BLOCK_SIZE, "big")


class BBCipher:
    """PSP BBCipher - AMCTRL's keystream generator, in a PyCryptodome shaped interface.

    Usage:
        cipher = BBCipher.new(enc_mode, key, seed)
        cipher.update(pgd_header.key)   # required, result discarded - see below
        plaintext = cipher.update(ciphertext)

    The first update() call takes the header key rather than data, and its result should be
    thrown away: pushing the key through update() spends keystream block 0, so real data
    starts at block 1 where the format expects it. Callers must make that call regardless.

    Decrypt only. AMCTRL has an encrypt direction; nothing here writes PGDs, so it is left
    unimplemented rather than carried as untested code.

    enc_mode 2 keys off KIRK's per-console key, which cannot be derived without the
    console's fuse ID, so those files cannot be decrypted here. Their BBMac check normally
    fails first, for the same reason, so this rarely gets reached.
    """

    PER_CONSOLE = 0x2

    @classmethod
    def new(cls, enc_mode: int, key: Optional[bytes] = None, seed: int = 0) -> "BBCipher":
        """Create a new BBCipher object"""
        return cls(enc_mode, key, seed)

    def __init__(self, enc_mode: int, key: Optional[bytes] = None, seed: int = 0):
        self.enc_mode = enc_mode
        self.seed = seed
        self.key = bytes(key) if key else bytes(BLOCK_SIZE)
        self.buf = bytearray(BLOCK_SIZE)
        self.current_seed = seed
        self.kirk = KirkEngine()

    def update(self, data: bytes) -> bytes:
        """Decrypt `data` - or, on the first call, take it as the header key"""
        if not data:
            return b""

        if len(data) % BLOCK_SIZE:
            raise BBCipherError(f"Data length {len(data)} is not a multiple of {BLOCK_SIZE}")

        if self.current_seed == self.seed:
            # First call: fold the header key into the hash the keystream is built from
            self.buf[:] = xor_cipher.cyclic_xor(bytes(data[:BLOCK_SIZE]), self.key)

        out = bytearray()
        for offset in range(0, len(data), CHUNK_SIZE):
            out += self._keystream_xor(data, offset, min(CHUNK_SIZE, len(data) - offset))

        return bytes(out)

    def _keystream_xor(self, data: bytes, data_offset: int, length: int) -> bytes:
        """Build `length` bytes of keystream and XOR it over the data"""
        buf = bytearray(length + KIRK_HEADER_SIZE)
        head = slice(KIRK_HEADER_SIZE, KIRK_HEADER_SIZE + BLOCK_SIZE)

        # Turn the stored hash into this chunk's key
        buf[head] = xor_cipher.cyclic_xor(bytes(self.buf), AMCTRL_HASHKEY_5)
        if self.enc_mode == self.PER_CONSOLE:
            keyseed, command = PER_CONSOLE_KEYSEED, KirkCommand.DECRYPT_PERCONSOLE
        else:
            keyseed, command = CIPHER_KEYSEED_HASH, KirkCommand.DECRYPT_STATIC
        decrypted = _scramble(self.kirk, buf, BLOCK_SIZE, keyseed, KirkMode.DECRYPT_CBC, command)
        block_key = xor_cipher.cyclic_xor(bytes(decrypted), AMCTRL_HASHKEY_4)

        # Past the first chunk, the previous block's counter carries into the keystream head
        if self.current_seed > 0x1:
            carry = bytearray(block_key)
            struct.pack_into("<I", carry, 0xC, self.current_seed - 1)
        else:
            carry = bytes(BLOCK_SIZE)

        # Counter blocks: 12 bytes of block key, then a little endian block index
        for offset in range(KIRK_HEADER_SIZE, length + KIRK_HEADER_SIZE, BLOCK_SIZE):
            buf[offset:offset + 0xC] = block_key[:0xC]
            struct.pack_into("<I", buf, offset + 0xC, self.current_seed)
            self.current_seed += 1

        keystream = _scramble(self.kirk, buf, length, CIPHER_KEYSEED_KEYSTREAM,
                              KirkMode.DECRYPT_CBC, KirkCommand.DECRYPT_STATIC)
        keystream[:BLOCK_SIZE] = xor_cipher.cyclic_xor(bytes(keystream[:BLOCK_SIZE]), bytes(carry))

        return xor_cipher.cyclic_xor(bytes(data[data_offset:data_offset + length]), bytes(keystream))
