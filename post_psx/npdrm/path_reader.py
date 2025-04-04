import io
import logging
import multiprocessing
import os
import pathlib
import re
from copy import copy

from common.iso_path_reader.methods.base import IsoPathReader
from common.iso_path_reader.methods.chunked_hash_trait import ChunkedHashTrait
from post_psx.npdrm.pkg import Pkg
from post_psx.path_reader import PostPsxPathReader
from post_psx.utils.eboot_pbp import EbootPBPFile
from post_psx.utils.npd import NPDFile
from post_psx.utils.iso_bin_enc import IsoBinEncFile
from post_psx.utils.pspedat import PSPEdatFile
from ps3.self_parser import SELFDecrypter
from utils import pycdlib
from utils.files import OffsetFile
from utils.pycdlib.decrypted_file_io import DecryptedFileIO

LOGGER = logging.getLogger(__name__)


class DecryptedFileReader(DecryptedFileIO):
    def __init__(self, ino, logical_block_size, pkg, entry):
        super().__init__(ino, logical_block_size, buffer_blocks=65536 // logical_block_size)
        self.pkg = pkg
        self.entry = entry
        self.pkg.init_cipher(ino.extent_location(), entry.key)

    def seek(self, offset, whence=0):
        super().seek(offset, whence)
        self.pkg.init_cipher(
            self._ctxt.ino.extent_location() + (self._offset // self.logical_block_size), self.entry.key
        )

    def decrypt_blocks(self, blocks):
        return self.pkg.decrypt(blocks)


class NPDRMPathReader(ChunkedHashTrait, PostPsxPathReader, IsoPathReader):
    volume_type = "npdrm"

    def __init__(self, iso: Pkg, fp, parent_container):
        super().__init__(iso, fp, parent_container)
        pkg_header = self.iso.pkg_header
        self.fp = OffsetFile(self.fp, pkg_header.data_offset, pkg_header.data_offset + pkg_header.data_size)
        self._decryption_status = {"edat": 1, "eboot": 1}
        self.edat_key = None
        self.self_key = None

    @property
    def decryption_status(self):
        if self._decryption_status["edat"] == 1 and self._decryption_status["eboot"] == 1:
            return "decrypted"
        elif self._decryption_status["edat"] == 0 and self._decryption_status["eboot"] == 1:
            return "eboot only"
        else:
            return "encrypted"

    def get_edat_key(self, pbar_manager):
        keys_to_try = self._get_potential_keys()

        # Find relevant files
        files = self._find_key_files()
        edat_file, eboot_file, sprx_file = files['edat'], files['eboot'], files['sprx']

        # Try to decrypt EDAT file directly with keys
        if edat_file:
            for edat_key in keys_to_try:
                if self.test_key(edat_key, edat_file):
                    LOGGER.info("Found EDAT/SELF key: %s", edat_key.hex())
                    return edat_key, edat_key

        # Try to extract key from EBOOT or SPRX
        if eboot_file or sprx_file:
            # Process EBOOT file
            if eboot_file:
                eboot_decryptor = self._create_decryptor(eboot_file)
                if eboot_decryptor is None:
                    return None, None

                # Try to decrypt with potential keys
                self_key = self._try_decrypt_with_keys(eboot_decryptor, keys_to_try, edat_file)
                if self_key:
                    LOGGER.info("Found SELF key: %s", self_key.hex())
                    return None, self_key

                if not eboot_decryptor.data_keys:
                    self._decryption_status["eboot"] = 0
                    return None, None

            # Process SPRX file if needed
            if sprx_file:
                sprx_decryptor = self._create_decryptor(sprx_file)
                if sprx_decryptor is None:
                    return None, None

                # Try to decrypt with potential keys
                self_key = self._try_decrypt_with_keys(sprx_decryptor, keys_to_try, edat_file)
                if self_key:
                    LOGGER.info("Found SELF key: %s", self_key.hex())
                    return None, self_key

            # If we have a decrypted EBOOT and an encrypted file (EDAT or SPRX), try brute force search
            if eboot_file and (edat_file or sprx_file):
                encrypted_file = self._prepare_search_target(edat_file, sprx_file)
                if encrypted_file:
                    eboot_elf = eboot_decryptor.get_decrypted_elf()
                    eboot_elf.seek(0, 2)
                    total_candidates = eboot_elf.tell() - 15

                    # Determine number of processes
                    num_processes = multiprocessing.cpu_count()

                    # Create enlighten manager and start the search
                    result = self.process_chunks(
                        pbar_manager,
                        eboot_elf,
                        encrypted_file,
                        total_candidates,
                        num_processes
                    )

                    if result:
                        # Store the key in the DB
                        if self.db:
                            title_id = self.iso.pkg_header.title_id.decode("utf-8")
                            c = self.db.cursor()
                            c.execute('INSERT INTO dev_klics VALUES (?, ?, NULL)', [result, title_id])
                            self.db.commit()
                        if eboot_decryptor.self_key and eboot_decryptor.self_key != result:
                            LOGGER.info("Found EDAT key: %s", result.hex())
                            LOGGER.info("Found SELF key: %s", eboot_decryptor.self_key.hex())
                            return result, eboot_decryptor.self_key
                        else:
                            LOGGER.info("Found EDAT/SELF key: %s", result.hex())
                            return result, result

        return None, None

    def _get_potential_keys(self):
        """Get a list of potential keys to try."""
        keys_to_try = []
        file_dir = pathlib.Path(
            self.parent_container.get_file_path(
                self.parent_container.get_file(str(pathlib.Path(self.fp.name).parent))
            ))

        try:
            title_id = self.iso.pkg_header.title_id.decode("utf-8")
            # Check for a RAP file in the directory
            rap_path = str((file_dir / title_id).with_suffix(".rap"))
            try:
                with self.parent_container.open_file(self.parent_container.get_file(rap_path)) as f:
                    keys_to_try.append(NPDFile.rap_to_rif(f.read()))
            except FileNotFoundError:
                pass
        except (UnicodeDecodeError, AttributeError):
            pass

        # Check the key db if it exists
        if self.db:
            c = self.db.cursor()
            # Try to find a rap file with a title
            rap = c.execute('SELECT * FROM raps WHERE title_id = ?', [title_id]).fetchone()
            if rap and len(rap[0]) == 16:
                keys_to_try.append(NPDFile.rap_to_rif(rap[0]))

            # Try to find a match. If no matches, just load the entire klics list
            keys = c.execute('SELECT * FROM dev_klics WHERE title_id = ?', [title_id]).fetchall()
            if keys:
                for key in keys:
                    keys_to_try.append(key[0])
            else:
                keys = c.execute('SELECT * FROM dev_klics').fetchall()
                for key in keys:
                    keys_to_try.append(key[0])

        # Add standard keys
        keys_to_try.append(bytes(NPDFile.NP_KLIC_FREE))
        keys_to_try.append(bytes(bytearray(16)))

        return set(keys_to_try)

    def _find_key_files(self):
        """Find and return the EDAT, EBOOT, and SPRX files."""
        root_dir = self.get_root_dir()

        edat_file = None
        for file in self.iso_iterator(root_dir, recursive=True):
            if self.get_file_path(file).lower().endswith(".edat"):
                inode = pycdlib.inode.Inode()
                inode.parse(file.file_offset // 16, file.file_size, self.fp, 16)
                with DecryptedFileReader(inode, 16, self.iso, file) as f:
                    if f.read(0x4) == b"NPD\x00" and self.get_file_size(file) > 0:
                        edat_file = file
                        break

        eboot_file = next((file for file in self.iso_iterator(root_dir, recursive=True) if
                           self.get_file_path(file).lower().endswith("eboot.bin")), None)
        sprx_file = next((file for file in self.iso_iterator(root_dir, recursive=True) if
                          self.get_file_path(file).lower().endswith(".sprx")), None)

        return {
            'edat': edat_file,
            'eboot': eboot_file,
            'sprx': sprx_file
        }

    def _create_decryptor(self, file):
        """Create and initialize a SELFDecrypter for the given file."""
        try:
            inode = pycdlib.inode.Inode()
            inode.parse(file.file_offset // 16, file.file_size, self.fp, 16)

            with DecryptedFileReader(inode, 16, self.iso, file) as f:
                decryptor = SELFDecrypter(f)
                if not decryptor.load_headers():
                    return None
                return decryptor
        except Exception as e:
            LOGGER.error(f"Failed to create decryptor for {self.get_file_path(file)}: {str(e)}")
            return None

    def _try_decrypt_with_keys(self, decryptor, keys_to_try, edat_file=None):
        npd = decryptor.get_npd_header()

        # Not an npdrm self, ignore
        if npd is None:
            if not decryptor.load_metadata():
                return None
            return None

        # Determine if we need a key
        need_klic = True
        if npd.license == 3:
            need_klic = not decryptor.load_metadata()

        # Try each key
        if need_klic:
            for edat_key in keys_to_try:
                decryptor.self_key = edat_key
                if decryptor.load_metadata():
                    if not edat_file or self.test_key(edat_key, edat_file):
                        return decryptor.self_key

        return None

    def _prepare_search_target(self, edat_file, sprx_file):
        """Prepare the target file for key search."""
        if edat_file:
            try:
                inode = pycdlib.inode.Inode()
                inode.parse(edat_file.file_offset // 16, edat_file.file_size, self.fp, 16)
                with DecryptedFileReader(inode, 16, self.iso, edat_file) as f:
                    edat_data = io.BytesIO(f.read())
                    return NPDFile(edat_data, os.path.basename(self.get_file_path(edat_file)), None)
            except Exception as e:
                LOGGER.error(f"Failed to prepare EDAT file for search: {str(e)}")

        if sprx_file:
            try:
                inode = pycdlib.inode.Inode()
                inode.parse(sprx_file.file_offset // 16, sprx_file.file_size, self.fp, 16)
                with DecryptedFileReader(inode, 16, self.iso, sprx_file) as f:
                    self_data = io.BytesIO(f.read())
                    decrypter = SELFDecrypter(self_data, os.path.basename(self.get_file_path(sprx_file)))
                    decrypter.load_headers()
                    return decrypter
            except Exception as e:
                LOGGER.error(f"Failed to prepare SPRX file for search: {str(e)}")

        return None

    def process_chunks(self, manager, elf, encrypted_file, total_candidates, num_processes):
        # Create main progress bar
        bar_format = ('{desc}{desc_pad}{percentage:3.0f}%|{bar}| '
                      'Processed: {count}/{total} '
                      '[{elapsed}<{eta}, {rate:.2f}{unit_pad}{unit}/s]')

        pb_main = manager.counter(
            total=total_candidates,
            desc='Searching for key:',
            unit='keys',
            bar_format=bar_format,
            leave=False,
        )

        # Shared counter for progress tracking
        m = multiprocessing.Manager()
        progress = m.Value('i', 0)
        progress_lock = m.Lock()

        def create_chunks(total, num_processes):
            chunk_size = max(1000, total // (num_processes * 10))
            for i in range(0, total, chunk_size):
                yield (i, min(chunk_size, total - i))

        chunks = [(pos, size, elf, encrypted_file, total_candidates, progress, progress_lock)
                  for pos, size in create_chunks(total_candidates, num_processes)]

        found_key = None
        last_progress = 0
        with multiprocessing.Pool(processes=num_processes) as pool:
            try:
                results = pool.imap_unordered(self._test_chunk_wrapper, chunks)

                while True:
                    try:
                        # Check for results without blocking
                        result = results.next(timeout=0.1)
                        if result:
                            found_key = result
                            pool.terminate()
                            break
                    except StopIteration:
                        break
                    except multiprocessing.TimeoutError:
                        pass

                    # Update progress bar
                    current_progress = progress.value
                    if current_progress > last_progress:
                        pb_main.update(current_progress - last_progress)
                        last_progress = current_progress

            except Exception as e:
                LOGGER.error(f"Error in key search: {str(e)}")
            finally:
                pb_main.close(clear=True)

        return found_key

    @staticmethod
    def _test_chunk_wrapper(args):
        start_pos, chunk_size, elf, encrypted_file, total_candidates, progress, progress_lock = args
        try:
            elf.seek(start_pos)
            local_progress = 0

            for i in range(chunk_size):
                current_pos = start_pos + i
                if current_pos >= total_candidates:
                    break

                edat_key = elf.read(16)
                elf.seek(current_pos + 1)

                local_progress += 1
                if local_progress % 100 == 0:  # Batch progress updates to reduce lock contention
                    with progress_lock:
                        progress.value += 100

                try:
                    if isinstance(encrypted_file, NPDFile) and encrypted_file.decrypt_block(0, edat_key) != -1:
                        return edat_key
                    elif isinstance(encrypted_file, SELFDecrypter):
                        encrypted_file.self_key = edat_key
                        if encrypted_file.load_metadata():
                            return edat_key

                except Exception as e:
                    LOGGER.debug(f"Failed to test key at position {current_pos}: {str(e)}")
                    continue

        except Exception as e:
            LOGGER.error(f"Error processing chunk starting at {start_pos}: {str(e)}")

        return None

    def test_key(self, key, file):
        file_path = self.get_file_path(file)
        inode = pycdlib.inode.Inode()
        inode.parse(file.file_offset // 16, file.file_size, self.fp, 16)
        with DecryptedFileReader(inode, 16, self.iso, file) as f, \
                NPDFile(f, os.path.basename(file_path), key) as f:
            return f.decrypt_block(0, key) != -1

    def get_root_dir(self):
        return next(self.iso.entries()).directory

    def iso_iterator(self, base_dir, recursive=False, include_dirs=False):
        for entry in base_dir.entries:
            if self.is_directory(entry) and not include_dirs:
                continue
            file_path = self.get_file_path(entry)
            # Check if this is a multi-disc file and spawn a file for each disc
            if file_path.lower().endswith("eboot.pbp"):
                inode = pycdlib.inode.Inode()
                inode.parse(entry.file_offset // 16, entry.file_size, self.fp, 16)
                with DecryptedFileReader(inode, 16, self.iso, entry) as f:
                    pbp = EbootPBPFile(f)
                    if pbp.load_header():
                        if pbp.num_discs > 1:
                            disc_entry = copy(entry)
                            for disc_num in range(pbp.num_discs):
                                disc_entry.name_decoded = entry.name_decoded.replace("EBOOT.PBP", f"EBOOT.{disc_num+1}.pbp")
                                yield disc_entry
                        else:
                            yield entry
            else:
                yield entry

        if not recursive:
            return
        for dir in base_dir.directories.values():
            yield from self.iso_iterator(dir, recursive)

    def get_file(self, path):
        normalized_path = path.strip('/')

        if not normalized_path or normalized_path == ".":
            return self.get_root_dir()

        for file in self.iso_iterator(self.get_root_dir(), recursive=True):
            if file.name_decoded == normalized_path:
                return file

        raise FileNotFoundError()

    def get_file_date(self, file):
        return None

    def get_file_path(self, file):
        return file.name_decoded

    def open_file(self, file):
        inode = pycdlib.inode.Inode()
        inode.parse(file.file_offset // 16, file.file_size, self.fp, 16)
        f = DecryptedFileReader(inode, 16, self.iso, file)
        file_path = self.get_file_path(file)
        if file_path.lower().endswith("edat"):
            f.__enter__()
            magic = f.read(0x8)
            if magic == b"\x00PSPEDAT":
                edat_file = PSPEdatFile(f, os.path.basename(file_path), self.edat_key)
                file_size = edat_file.size
            else:
                edat_file = NPDFile(f, os.path.basename(file_path), self.edat_key)
                file_size = edat_file.edat_header.file_size
                if not edat_file.validate_npd_hashes(os.path.basename(file_path)):
                    LOGGER.warning("Could not validate header hashes for %s", file_path)
            if file_size == 0:
                f.__exit__()
                f = io.BytesIO(b"")
            elif isinstance(edat_file, NPDFile) and not self.edat_key:
                self._decryption_status["edat"] = 0
                LOGGER.warning("Could not locate decryption key for %s. File will not be decrypted", file_path)
            else:
                f = edat_file
        elif file_path.lower().endswith("iso.bin.enc"):
            f.__enter__()
            iso_bin_file = IsoBinEncFile(f, os.path.basename(file_path), self.edat_key)
            if iso_bin_file.edat_header.file_size == 0:
                f.__exit__()
                f = io.BytesIO(b"")
            if not self.edat_key:
                self._decryption_status["edat"] = 0
                LOGGER.warning("Could not locate decryption key for %s. File will not be decrypted", file_path)
            elif not iso_bin_file.test_decrypt(self.edat_key):
                LOGGER.warning("Decryption failed for %s, file will not be decrypted", file_path)
            else:
                f = iso_bin_file
        elif file_path.lower().endswith("eboot.pbp") or re.match(r".*eboot\.[0-9]\.pbp$", file_path.lower()):
            eboot_match = re.match(r".*eboot\.([0-9])\.pbp$", file_path.lower())
            disc_num = int(eboot_match.group(1)) if eboot_match else 1
            f.__enter__()
            eboot_pbp_file = EbootPBPFile(f, disc_num-1)
            if not eboot_pbp_file.load_header():
                LOGGER.warning("Decryption failed for %s, file will not be decrypted", file_path)
            else:
                f = eboot_pbp_file

        f.name = self.get_file_path(file)
        return f

    def get_file_sector(self, file):
        raise NotImplementedError

    def get_file_size(self, file):
        file_path = self.get_file_path(file)
        if file_path.lower().endswith("edat") or file_path.lower().endswith("iso.bin.enc"):
            inode = pycdlib.inode.Inode()
            inode.parse(file.file_offset // 16, file.file_size, self.fp, 16)
            with DecryptedFileReader(inode, 16, self.iso, file) as f:
                if file_path.lower().endswith("iso.bin.enc"):
                    edat_size = IsoBinEncFile(f, os.path.basename(file_path), self.edat_key).edat_header.file_size
                else:
                    magic = f.read(0x8)
                    if magic == b"\x00PSPEDAT":
                        return PSPEdatFile(f, os.path.basename(file_path), self.edat_key).size
                    else:
                        edat_size = NPDFile(f, os.path.basename(file_path), self.edat_key).edat_header.file_size

                if edat_size == 0 or self.edat_key:
                    return edat_size
        elif file_path.lower().endswith("eboot.pbp") or re.match(r".*eboot\.[0-9]\.pbp$", file_path.lower()):
            eboot_match = re.match(r".*eboot\.([0-9])\.pbp$", file_path.lower())
            disc_num = int(eboot_match.group(1)) if eboot_match else 1

            inode = pycdlib.inode.Inode()
            inode.parse(file.file_offset // 16, file.file_size, self.fp, 16)
            with DecryptedFileReader(inode, 16, self.iso, file) as f:
                pbp = EbootPBPFile(f, disc_num-1)
                if pbp.load_header():
                    return pbp.size

        return file.file_size

    def is_directory(self, file):
        return file.is_dir

    def get_pvd(self):
        return None

    def get_pvd_info(self):
        return {}

    @property
    def system_type(self):
        if self.iso.pkg_header.pkg_platform == self.iso.PKG_PLATFORM_TYPE_PS3:
            return "ps3"

        title_id = self.iso.pkg_header.title_id
        psp_title_ids = [b"UL", b"UC", b"G", b"H", b"W", b"Y"]
        ps3_title_ids = [b"BL", b"BC"]
        if title_id[0:2] in ps3_title_ids:
            return "ps3"
        elif any(title_id.startswith(tid) for tid in psp_title_ids):
            return "psp"
        elif title_id[0:3] == b"PCS":
            return "vita"

        if self.iso.pkg_ext_header:
            if self.iso.pkg_ext_header.pkg_key_id == 0x1:
                return "psp"
            elif self.iso.pkg_ext_header.pkg_key_id == 0xC0000002:
                return "vita"
