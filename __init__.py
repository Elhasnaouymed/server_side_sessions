import os
import json
import hashlib
from typing import Any, Generator
from contextlib import contextmanager
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from . import exceptions as errors

__author__ = 'Mohamed Elhasnaouy'
__email__ = 'elhasnaouymed@zp1.net'
__license__ = 'GNU GPLv2'
__summary__ = 'Server Side Sessions, CRUD with AES encryption, or no encryption.'
__version__ = '0.0.1'
__status__ = 'Development'
__title__ = 'Server Side Sessions'


class ServerSideSession:
    _AES = '.aes'
    _JSON = '.json'

    def __init__(self, secret: str = None, directory: str = None, unencrypt=False, mkdir=True):
        """
        Lets you deal with Sessions as Python dictionaries, CRUD them to a file for each session,
        Encrypted at rest by default, you can disable it.
        :param secret: Secret to use in AES encryption.
        :param directory: Where to store the session files.
        :param unencrypt: Choose to not encrypt Sessions at rest (for speed).
        :param mkdir: make directory if it doesn't exist (recommended).
        """
        self._initialized = False
        self._master_key = None
        self._secret = secret
        self._directory = directory
        self._unencrypt = unencrypt
        self._mkdir = mkdir
        # > initialize only when all arguments are specified
        if self._secret is not None and self._directory is not None:
            self.initialize()

    def initialize(self, secret: str = None, directory: str = None, unencrypt: bool = None, mkdir: bool = None):
        """
        Initializes the instance and makes it ready to use.
        :param secret: Same as in __init__.
        :param directory: Same as in __init__.
        :param unencrypt: Same as in __init__.
        :param mkdir: Same as in __init__.
        :return: None.
        """
        # > prevent initializing twice
        if self._initialized:
            raise errors.ServerSideSessionAlreadyInitialized()
        # > overwrite newly specified variables, otherwise don't
        self._secret = secret if secret is not None else self._secret
        self._directory = directory if directory is not None else self._directory
        self._unencrypt = unencrypt if unencrypt is not None else self._unencrypt
        self._mkdir = mkdir if mkdir is not None else self._mkdir
        # > check if all variables are specified, otherwise error out
        if self._secret is None or self._directory is None or self._unencrypt is None or self._mkdir is None:
            raise errors.ServerSideSessionInitializationError()
        # > make directory if requested
        if self._mkdir:
            os.makedirs(self._directory, exist_ok=True)
        self._master_key = hashlib.sha256(self._secret.encode("utf-8")).digest()  # hash the secret for more entropy
        self._initialized = True  # mark as initialized

    @property
    def initialized(self):
        """
        Read only initialization status.
        :return: bool
        """
        return self._initialized

    def check_initialization(self) -> None:
        """
        Check if the instance has already been initialized.
        :return: None.
        :raise ServerSideSessionNotInitialized: if the instance is not initialized.
        """
        if not self._initialized:
            raise errors.ServerSideSessionNotInitializedError()

    def _derive_key(self, salt: bytes) -> bytes:
        """
        Only used internally to derive keys for AES encryption.
        :param salt: your random salt.
        :return: key as bytes.
        """
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=200_000, backend=default_backend(), )
        return kdf.derive(self._master_key)

    def _encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt using AES-GCM.
        :param plaintext: bytes to encrypt.
        :return: ciphertext as bytes.
        """
        self.check_initialization()
        salt = os.urandom(16)
        iv = os.urandom(12)
        key = self._derive_key(salt)
        aes = AESGCM(key)
        ciphertext = aes.encrypt(iv, plaintext, None)
        blob = salt + iv + ciphertext
        return blob

    def _decrypt(self, data: bytes) -> bytes:
        """
        Decrypt using AES-GCM.
        :param data: bytes to decrypt.
        :return: plaintext as bytes.
        """
        self.check_initialization()
        salt = data[:16]
        iv = data[16:28]
        ciphertext = data[28:]
        key = self._derive_key(salt)
        aes = AESGCM(key)
        try:
            plaintext = aes.decrypt(iv, ciphertext, None)
            return plaintext
        except InvalidTag:
            raise errors.ServerSideSessionCorruptError()

    def list_sessions(self) -> list:
        """
        List all available sessions by names.
        :return: list of session names.
        """
        self.check_initialization()
        sessions = set()  # don't list same names twice
        for filename in os.listdir(self._directory):
            if not os.path.isfile(os.path.join(self._directory, filename)):  # ignore none files
                continue
            name, ext = os.path.splitext(filename)
            # > add only .json and .aes files that are not considered hidden files (with . at start)
            if ext in [self._AES, self._JSON] and not filename.startswith('.'):
                sessions.add(name)
        return list(sessions)  # convert set into list

    @staticmethod
    def _remove_file(filepath: str) -> bool:
        """
        remove a file and don't error
        :param filepath: fullpath (relative or absolute) to file to remove.
        :return: bool.
        """
        try:
            os.remove(filepath)
            return True
        except OSError:
            return False

    @staticmethod
    def _write_file(filepath: str, data: bytes) -> bool:
        """
        write to a file and don't error
        :param filepath: fullpath (relative or absolute) to file to remove.
        :param data: bytes to write.
        :return: bool.
        """
        try:
            with open(filepath, 'wb') as file:
                file.write(data)
                return True
        except OSError:
            return False

    @staticmethod
    def _read_file(filepath: str) -> bytes | None:
        """
        read from file and ignore errors
        :param filepath: fullpath (relative or absolute) to file to remove.
        :return: bytes or None.
        """
        try:
            with open(filepath, 'rb') as file:
                return file.read()
        except OSError:
            return None

    def _write_session(self, name: str, session: dict) -> bool:
        """
        Write session dict to file, handles encryption if needed.
        :param name: session name.
        :param session: session dict.
        :return: bool.
        """
        self.check_initialization()
        data = json.dumps(session).encode()  # serialize the dict.
        # > generate both AES and JSON session file names
        aes_filepath = os.path.join(self._directory, name + self._AES)
        json_filepath = os.path.join(self._directory, name + self._JSON)
        # > check if raw write is selected
        if self._unencrypt:
            self._remove_file(aes_filepath)  # remove the encrypted session file if exists
            return self._write_file(json_filepath, data)  # write to raw json file and return status

        # when encryption is selected
        ciphertext = self._encrypt(data)  # encrypt the session data
        self._remove_file(json_filepath)  # remove the raw session file if exists
        return self._write_file(aes_filepath, ciphertext)  # write ciphertext and return state

    def _read_session(self, name: str) -> dict | None:
        """
        Read session dict from file, handles decryption if needed.
        :param name: session name.
        :return: session dict if found, None otherwise.
        """
        self.check_initialization()
        # > generate both AES and JSON session file names
        aes_filepath = os.path.join(self._directory, name + self._AES)
        json_filepath = os.path.join(self._directory, name + self._JSON)
        # > check if session doesn't exist and return None
        if not os.path.isfile(aes_filepath) and not os.path.isfile(json_filepath):
            return None
        # > check if session exists in both encrypted and raw types
        if os.path.isfile(aes_filepath) and os.path.isfile(json_filepath):
            # > choose the newest session file to be used, ignore the oldest
            session_filepath = aes_filepath if os.path.getmtime(aes_filepath) > os.path.getmtime(json_filepath) else json_filepath
        else:  # when only one session file is existed
            session_filepath = aes_filepath if os.path.isfile(aes_filepath) else json_filepath  # select the existed one session file to be used (JSON or AES)

        # > look for JSON file first and read from it
        name, ext = os.path.splitext(session_filepath)
        if ext == self._JSON:
            data = self._read_file(session_filepath)  # read file
            session = json.loads(data)  # deserialize
            return session  # return session as dict

        # > when AES is the session file type
        ciphertext = self._read_file(session_filepath)  # read file
        data = self._decrypt(ciphertext)  # decrypt
        session = json.loads(data)  # deserialize
        return session  # return session as dict

    @contextmanager
    def _get_session(self, name: str) -> Generator[dict[Any, Any]]:
        """
        Reads the session, passes it in a context manager as a dict (mutable), then writes the changes when you exit the context manager.
        :param name: session name.
        :return: dict in GeneratorContextManager.
        """
        self.check_initialization()
        session = self._read_session(name)  # read the session (can return None)
        session = {} if session is None else session  # create a dictionary if the session is new
        yield session  # return it
        if not self._write_session(name, session):  # write the changes
            raise errors.ServerSideSessionWriteError()
        # * Note: we always write to disk even if the session is not updated, for simplicity for now,
        #   because there are many variables to account for not just the session itself, like reading from AES file and next write should be JSON,
        #   We don't want to miss changing file types because the session hasn't been updated.

    def exists(self, name: str) -> bool:
        """
        Check if session exists.
        :param name: session name.
        :return: bool.
        """
        return name in self.list_sessions()

    def __getitem__(self, name: str):
        """
        Get Session, Write changes after you done.
        :param name: session name.
        :return: dict in GeneratorContextManager.
        """
        return self._get_session(name)

    def __delitem__(self, name: str):
        """
        Remove a Session permanently.
        :param name: session name.
        :return: None
        """
        aes_filepath = os.path.join(self._directory, name + self._AES)
        json_filepath = os.path.join(self._directory, name + self._JSON)
        self._remove_file(aes_filepath)
        self._remove_file(json_filepath)

    def __len__(self):
        return len(self.list_sessions())
