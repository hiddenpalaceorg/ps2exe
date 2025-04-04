import logging
import time
from enum import IntEnum

from Crypto.Cipher import AES
from Crypto.Hash import SHA1

from post_psx.types import KirkAES128CBCHeader, KirkSHA1Header
from post_psx.utils.kirk.keyvault import KIRK_4_7_KEYS

LOGGER = logging.getLogger(__name__)

# Every KIRK AES mode is CBC off an all-zero IV
NULL_IV = bytes(AES.block_size)

# Command 4 may only encrypt with the first 64 keys, command 7 may decrypt with all 128
MAX_ENCRYPT_KEYSEED = 0x3F
MAX_DECRYPT_KEYSEED = len(KIRK_4_7_KEYS) - 1

# Commands 5/8 key off the console's fuse ID, which we don't have, so this all-zero stand-in
# takes its place: 5 and 8 round trip against each other but never match real hardware.
# Anything needing a genuine per-console key (PGDs from DNAS-installed saves) stays opaque.
PER_CONSOLE_KEY = bytes(AES.block_size)

PRNG_STATE_SIZE = SHA1.digest_size  # 0x14
# An arbitrary constant folded into every reseed. No meaning beyond adding fixed entropy
PRNG_STIR_KEY = bytes.fromhex("a72e4cb6c334df85700149fcc087c477")
PRNG_SEED_SIZE = 0x100
DEFAULT_PRNG_SEED = b"KIRKENGINEINITIALIZATION"


class KirkCommand(IntEnum):
    """KIRK service numbers, as passed to sceUtilsBufferCopyWithRange().

    Other codebases name the ones used here after their key source instead: 4/7 as
    ENCRYPT_IV_0/DECRYPT_IV_0, 5/8 as ENCRYPT_IV_FUSE/DECRYPT_IV_FUSE.
    """
    DECRYPT_BOOTROM = 0
    DECRYPT_PRIVATE = 1
    DNAS_ENCRYPT = 2
    DNAS_DECRYPT = 3
    ENCRYPT_STATIC = 4
    ENCRYPT_PERCONSOLE = 5
    ENCRYPT_USER = 6
    DECRYPT_STATIC = 7
    DECRYPT_PERCONSOLE = 8
    DECRYPT_USER = 9
    PRIV_SIGVRY = 10
    HASH = 11
    ECDSA_GENKEY = 12
    ECDSA_MUL = 13
    PRNGEN = 14
    SEED = 15
    SIGGEN = 16
    SIGVRY = 17
    CERTVRY = 18


class KirkMode(IntEnum):
    """`mode` field of the commands 4~9 header."""
    ENCRYPT_CBC = 4
    DECRYPT_CBC = 5


class KirkSubmode(IntEnum):
    """Low 3 bits of the submode byte: where the commands 4~9 key comes from."""
    STATIC = 0  # Commands 4/7: keyseed indexes the on-chip key vault
    PER_CONSOLE = 1  # Commands 5/8: key derived from the console's fuse ID
    USER = 2  # Commands 6/9: caller-supplied key at header offset 0x14


class KirkError(Exception):
    """Base exception for KIRK errors.

    `code` is the value the hardware leaves in its result register for this failure.
    """
    code = None


class KirkInvalidModeError(KirkError):
    """The header's mode or submode doesn't match the command it was handed to"""
    code = 0x02


class KirkNotInitializedError(KirkError):
    """A command ran before the engine's PRNG was seeded"""
    code = 0x0C


class KirkUnsupportedCommandError(KirkError):
    """A command outside the 0~18 range, or one this engine doesn't implement"""
    code = 0x0D


class KirkInvalidSeedError(KirkError):
    """The header names a key seed the command can't produce a key for"""


class KirkInvalidEncryptSeedError(KirkInvalidSeedError):
    """Key seed outside the range an encryption command accepts"""
    code = 0x0E


class KirkInvalidDecryptSeedError(KirkInvalidSeedError):
    """Key seed outside the range a decryption command accepts"""
    code = 0x0F


class KirkDataSizeZeroError(KirkError):
    """The header declares an empty payload"""
    code = 0x10


class KirkEngine:
    """Software stand-in for the PSP's KIRK crypto engine.

    Only what AMCTRL asks for is implemented: AES-128-CBC against a key vault key
    (commands 4/7) or the per-console key (5/8), SHA-1 (11) and the PRNG (14). Anything
    else raises KirkUnsupportedCommandError.

    All four AES commands return the 0x14-byte header followed by their payload, so a
    caller always slices a fixed 0x14 off the front. On real hardware the decrypt
    commands return the payload alone; keeping the header makes the four uniform.

    The header layout, per-command keyseed ranges and error codes are all spelled out in
    this module rather than left implicit, because other KIRK implementations commonly
    disagree on all three. Background: https://www.psdevwiki.com/psp/Kirk
    """

    def __init__(self, seed: bytes = DEFAULT_PRNG_SEED, fuse_id: int = 0):
        self.is_initialized = False
        self.prng_data = bytes(PRNG_STATE_SIZE)
        self.kirk_init(seed, fuse_id)

    def kirk_init(self, seed: bytes = DEFAULT_PRNG_SEED, fuse_id: int = 0) -> None:
        """Seed the PRNG and enable the engine"""
        if seed:
            self.prng_data = self._sha1(KirkSHA1Header(len(seed)).pack() + seed)
        self._stir_prng()
        # Fuse ID halves as the hardware exposes them, at 0xBC100090 and 0xBC100094.
        # Nothing reads them yet - deriving the per-console key for commands 5/8 would.
        self.fuse_id_90 = fuse_id & 0xFFFFFFFF
        self.fuse_id_94 = (fuse_id >> 32) & 0xFFFFFFFF
        self.is_initialized = True

    def kirk_cmd4(self, inbuff: bytes) -> bytes:
        """Encrypt with AES-CBC-128 using a key vault key"""
        header, payload = self._read_cbc_header(inbuff, KirkMode.ENCRYPT_CBC, KirkSubmode.STATIC)
        encrypted = self._aes_cbc(payload, self._keyvault_key(header.keyseed, encrypt=True), decrypt=False)
        # The header goes out with the ciphertext, flipped to describe it, so the result can
        # be handed straight to the matching decrypt command
        header.mode = KirkMode.DECRYPT_CBC
        return header.pack() + encrypted

    def kirk_cmd5(self, inbuff: bytes) -> bytes:
        """Encrypt with AES-CBC-128 using the per-console key"""
        header, payload = self._read_cbc_header(inbuff, KirkMode.ENCRYPT_CBC, KirkSubmode.PER_CONSOLE)
        encrypted = self._aes_cbc(payload, PER_CONSOLE_KEY, decrypt=False)
        header.mode = KirkMode.DECRYPT_CBC
        return header.pack() + encrypted

    def kirk_cmd7(self, inbuff: bytes) -> bytes:
        """Decrypt with AES-CBC-128 using a key vault key"""
        header, payload = self._read_cbc_header(inbuff, KirkMode.DECRYPT_CBC, KirkSubmode.STATIC)
        key = self._keyvault_key(header.keyseed, encrypt=False)
        return header.pack() + self._aes_cbc(payload, key, decrypt=True)

    def kirk_cmd8(self, inbuff: bytes) -> bytes:
        """Decrypt with AES-CBC-128 using the per-console key"""
        header, payload = self._read_cbc_header(inbuff, KirkMode.DECRYPT_CBC, KirkSubmode.PER_CONSOLE)
        return header.pack() + self._aes_cbc(payload, PER_CONSOLE_KEY, decrypt=True)

    def kirk_cmd11(self, inbuff: bytes) -> bytes:
        """SHA-1 the payload the 4-byte header describes"""
        self._require_initialized()
        return self._sha1(inbuff)

    def kirk_cmd14(self, size: int) -> bytes:
        """Generate `size` pseudo random bytes"""
        self._require_initialized()
        if size <= 0:
            return b""

        out = bytearray()
        while len(out) < size:
            self._stir_prng()
            out += self.prng_data[:size - len(out)]

        return bytes(out)

    def sce_utils_buffer_copy_with_range(self, outsize: int, inbuff: bytes, insize: int, cmd: int) -> bytearray:
        """Run a KIRK command, dispatching on the service number.

        Commands 4/5/7/8 return the 0x14-byte header followed by at most `outsize` bytes
        of payload; 11 and 14 return their bare result. `insize` is unused - every command
        takes its input size from the header - and is kept to match the syscall signature.

        Returns a bytearray, which callers rely on to edit the result in place.
        """
        if cmd == KirkCommand.ENCRYPT_STATIC:
            result = self.kirk_cmd4(inbuff)
        elif cmd == KirkCommand.ENCRYPT_PERCONSOLE:
            result = self.kirk_cmd5(inbuff)
        elif cmd == KirkCommand.DECRYPT_STATIC:
            result = self.kirk_cmd7(inbuff)
        elif cmd == KirkCommand.DECRYPT_PERCONSOLE:
            result = self.kirk_cmd8(inbuff)
        elif cmd == KirkCommand.HASH:
            return bytearray(self.kirk_cmd11(inbuff))
        elif cmd == KirkCommand.PRNGEN:
            return bytearray(self.kirk_cmd14(outsize))
        else:
            raise KirkUnsupportedCommandError(f"KIRK command {cmd:#x} is not implemented")

        return bytearray(result[:KirkAES128CBCHeader.struct.size + outsize])

    def _require_initialized(self) -> None:
        if not self.is_initialized:
            raise KirkNotInitializedError("KIRK has not been seeded")

    def _read_cbc_header(self, inbuff: bytes, mode: KirkMode, submode: KirkSubmode):
        """Split a commands 4~9 buffer into its header and the payload it declares"""
        self._require_initialized()

        header_size = KirkAES128CBCHeader.struct.size
        if len(inbuff) < header_size:
            raise KirkDataSizeZeroError(f"Buffer of {len(inbuff)} bytes is too short to hold a KIRK header")

        header = KirkAES128CBCHeader.unpack(bytes(inbuff[:header_size]))
        if header.mode != mode:
            raise KirkInvalidModeError(f"Expected header mode {mode!r}, got {header.mode:#x}")
        if header.submode & 0x7 != submode:
            raise KirkInvalidModeError(f"Expected header submode {submode!r}, got {header.submode:#x}")
        if not header.data_size:
            raise KirkDataSizeZeroError("Header declares a zero length payload")

        return header, inbuff[header_size:header_size + header.data_size]

    @staticmethod
    def _keyvault_key(keyseed: int, encrypt: bool) -> bytes:
        """Look up a commands 4/7 key vault key"""
        max_keyseed = MAX_ENCRYPT_KEYSEED if encrypt else MAX_DECRYPT_KEYSEED
        if not 0 <= keyseed <= max_keyseed:
            error = KirkInvalidEncryptSeedError if encrypt else KirkInvalidDecryptSeedError
            raise error(f"Key seed {keyseed:#x} is outside the {max_keyseed:#x} keys this command can use")

        return KIRK_4_7_KEYS[keyseed]

    @staticmethod
    def _aes_cbc(payload: bytes, key: bytes, decrypt: bool) -> bytes:
        """AES-128-CBC whole blocks of `payload` off a null IV.

        KIRK is a block engine: a payload that is not a multiple of the block size leaves
        its trailing partial block untouched rather than padding it.
        """
        aligned = len(payload) - len(payload) % AES.block_size
        if aligned != len(payload):
            LOGGER.warning("KIRK payload of %d bytes is not block aligned, passing the trailing %d bytes through",
                           len(payload), len(payload) - aligned)

        cipher = AES.new(key, AES.MODE_CBC, NULL_IV)
        crypt = cipher.decrypt if decrypt else cipher.encrypt

        return crypt(bytes(payload[:aligned])) + bytes(payload[aligned:])

    @staticmethod
    def _sha1(inbuff: bytes) -> bytes:
        """The command 11 hash itself, minus the seeded check so kirk_init() can use it"""
        header_size = KirkSHA1Header.struct.size
        if len(inbuff) < header_size:
            raise KirkDataSizeZeroError(f"Buffer of {len(inbuff)} bytes is too short to hold a KIRK SHA-1 header")

        header = KirkSHA1Header.unpack(bytes(inbuff[:header_size]))
        if not header.data_size:
            raise KirkDataSizeZeroError("Header declares a zero length payload")

        return SHA1.new(bytes(inbuff[header_size:header_size + header.data_size])).digest()

    def _stir_prng(self) -> None:
        """Fold the clock and a fixed key into the PRNG state.

        Not the hardware's PRNG, which runs off the per-console key this engine cannot
        derive, so treat the output as non-reproducible filler rather than as KIRK
        randomness. Nothing decrypts with it: it only seeds the encryption direction.
        """
        seed = bytearray(PRNG_SEED_SIZE + KirkSHA1Header.struct.size)
        seed[:KirkSHA1Header.struct.size] = KirkSHA1Header(PRNG_SEED_SIZE).pack()
        seed[0x04:0x04 + PRNG_STATE_SIZE] = self.prng_data
        seed[0x18:0x1C] = int(time.time()).to_bytes(8, "little")[:4]
        seed[0x1C:0x1C + len(PRNG_STIR_KEY)] = PRNG_STIR_KEY

        self.prng_data = self._sha1(seed)
