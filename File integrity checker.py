import logging
import threading
import concurrent.futures
import datetime
import ctypes
import os
from pathlib import Path
import json
import hashlib
import time
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding, serialization
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from google.cloud import kms as google_kms
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
import boto3
from botocore.exceptions import NoCredentialsError
import argparse

# Configure logging
logging.basicConfig(filename='file_integrity.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class FileIntegrityChecker:
    SUPPORTED_HASH_ALGORITHMS = {
        'md5': hashlib.md5,
        'sha1': hashlib.sha1,
        'sha256': hashlib.sha256
    }
    CHUNK_SIZE = 4096
    IV_SIZE = 16

    def __init__(self, google_kms_client=None, azure_kms_client=None, aws_kms_client=None):
        self.integrity_results = []
        self.stored_hashes = {}
        self.lock = threading.Lock()
        self.google_kms_client = google_kms_client
        self.azure_kms_client = azure_kms_client
        self.aws_kms_client = aws_kms_client


    def calculate_file_hash(self, file_path, hash_algorithm):
        """
        Calculate the hash of a file using the specified hash algorithm.

        Args:
            file_path (str): Path to the file.
            hash_algorithm (str): Hashing algorithm to use.

        Returns:
            str: Calculated hash value.
        """
        try:
            hash_obj = self.SUPPORTED_HASH_ALGORITHMS[hash_algorithm]()
            with open(file_path, 'rb') as file:
                while True:
                    chunk = file.read(self.CHUNK_SIZE)
                    if not chunk:
                        break
                    hash_obj.update(chunk)
            return hash_obj.hexdigest()
        except (FileNotFoundError, PermissionError) as e:
            logger.error(f"Error reading file '{file_path}': {e}")
            raise

    def validate_input_path(self, path):
        """
        Validate the input file or directory path.

        Args:
            path (str): Input path to validate.
        """
        if not Path(path).exists():
            raise FileNotFoundError(f"Path '{path}' does not exist.")
        if not os.access(path, os.R_OK):
            raise PermissionError(f"Permission denied for path '{path}'.")

    def validate_file_path(self, file_path):
        """
        Validate the given file path.

        Args:
            file_path (str): File path to validate.
        """
        if not Path(file_path).is_file():
            raise FileNotFoundError(f"'{file_path}' is not a valid file path.")
        if not os.access(file_path, os.R_OK):
            raise PermissionError(f"Permission denied for file '{file_path}'.")

    def validate_directory_path(self, dir_path):
        """
        Validate the given directory path.

        Args:
            dir_path (str): Directory path to validate.
        """
        if not Path(dir_path).is_dir():
            raise IsADirectoryError(f"'{dir_path}' is not a valid directory path.")
        if not os.access(dir_path, os.R_OK):
            raise PermissionError(f"Permission denied for directory '{dir_path}'.")

    def get_stored_hash(self, file_path):
        """
        Retrieve the stored hash value for a file.

        Args:
            file_path (str): Path to the file.

        Returns:
            str: Stored hash value or None if not found.
        """
        return self.stored_hashes.get(file_path)

    def store_hash(self, file_path, file_hash):
        """
        Store the hash value for a file.

        Args:
            file_path (str): Path to the file.
            file_hash (str): Hash value to store.
        """
        self.stored_hashes[file_path] = file_hash

    def load_stored_hashes(self, file_path):
        """
        Load the stored hashes from a JSON file.

        Args:
            file_path (str): Path to the JSON file.
        """
        if Path(file_path).is_file():
            try:
                with open(file_path, 'r') as file:
                    self.stored_hashes = json.load(file)
            except (FileNotFoundError, json.JSONDecodeError) as e:
                logger.error(f"Error loading stored hashes from '{file_path}': {e}")
                raise

    def save_stored_hashes(self, file_path):
        """
        Save the stored hashes to a JSON file.

        Args:
            file_path (str): Path to the JSON file.
        """
        try:
            with open(file_path, 'w') as file:
                json.dump(self.stored_hashes, file)
        except IOError as e:
            logger.error(f"Error saving stored hashes to '{file_path}': {e}")
            raise

    def log_audit_event(self, event_type, file_path, status):
        """
        Log an audit event.

        Args:
            event_type (str): Type of event.
            file_path (str): Path to the file.
            status (str): Status of the file (e.g., "OK", "MODIFIED").
        """
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"{timestamp} - Event: {event_type} - File: {file_path} - Status: {status}"

        with self.lock:
            logging.info(log_entry)

    def parallel_hash_storage(self, file_paths, hash_algorithm):
        """
        Perform parallel hash storage for multiple files.

        Args:
            file_paths (list): List of file paths.
            hash_algorithm (str): Hashing algorithm to use.
        """
        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = []
            for file_path in file_paths:
                future = executor.submit(self.calculate_file_hash, file_path, hash_algorithm)
                futures.append((file_path, future))
            for file_path, future in futures:
                try:
                    file_hash = future.result()
                    self.store_hash(file_path, file_hash)
                except Exception as e:
                    logger.exception("Failed to calculate hash for file: %s", file_path)
                    raise

    def parallel_integrity_checks(self, file_paths, hash_algorithm):
        """
        Perform parallel integrity checks for multiple files.

        Args:
            file_paths (list): List of file paths.
            hash_algorithm (str): Hashing algorithm to use.
        """
        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = []
            for file_path in file_paths:
                future = executor.submit(self.perform_integrity_check, file_path, hash_algorithm)
                futures.append(future)
            for future in futures:
                future.result()

    def perform_integrity_check(self, file_path, hash_algorithm):
        """
        Perform integrity check for a file.

        Args:
            file_path (str): Path to the file.
            hash_algorithm (str): Hashing algorithm to use.
        """
        try:
            file_hash = self.calculate_file_hash(file_path, hash_algorithm)
            stored_hash = self.get_stored_hash(file_path)
            status = "OK" if file_hash == stored_hash else "MODIFIED"

            self.log_audit_event("Integrity Check", file_path, status)

            with self.lock:
                logging.info(f"File: {file_path}\tStatus: {status}")

            self.integrity_results.append({
                "file_path": file_path,
                "status": status
            })
        except Exception as e:
            logger.exception(f"Error performing integrity check for file '{file_path}': {e}")

    def get_files_in_directory(self, directory, excluded_filetypes=None):
        file_paths = []
        for file in Path(directory).rglob("*"):
            if file.is_file() and (excluded_filetypes is None or not any(file.suffix == ft for ft in excluded_filetypes)):
                file_paths.append(str(file))
        return file_paths

    def exclude_files_from_results(self, results, excluded_files):
        return [result for result in results if result['file_path'] not in excluded_files]

    def load_exclusion_list(self, exclusion_list_file):
        exclusion_list = []
        with open(exclusion_list_file, 'r') as file:
            for line in file:
                line = line.strip()
                if line:
                    exclusion_list.append(line)
        return exclusion_list

    def initialize_tpm(self):
        try:
            tpm = ctypes.windll.Tbsip_OpenTPM()
            return tpm
        except Exception as e:
            logger.exception("Failed to initialize TPM: %s", str(e))

    def store_hashes_in_tpm(self, tpm, hashes):
        try:
            for file_path, file_hash in hashes.items():
                file_hash_bytes = file_hash.encode("utf-8")
                tpm.StoreHash(file_path, file_hash_bytes)
            logger.info("Hashes stored in TPM.")
        except Exception as e:
            logger.exception("Failed to store hashes in TPM: %s", str(e))

    def retrieve_stored_hashes(self, tpm):
        try:
            buffer_size = ctypes.c_ulong(1024)
            buffer = ctypes.create_string_buffer(buffer_size.value)
            tpm.GetStoredHashes(buffer, buffer_size)
            self.stored_hashes = json.loads(buffer.value.decode("utf-8"))
            logger.info("Hashes retrieved from TPM:")
            for file_path, file_hash in self.stored_hashes.items():
                logger.info(f"File: {file_path}\tHash: {file_hash}")
        except Exception as e:
            raise RuntimeError("Failed to retrieve hashes from TPM: " + str(e))

    def check_tpm_status(self):
        try:
            tpm_status = ctypes.windll.Tbsip_GetTpmStatus()
            if tpm_status == 0:
                logger.info("TPM is available and enabled on this system.")
            else:
                logger.info("TPM is not available or not enabled on this system.")
        except Exception as e:
            logger.exception("Failed to check TPM status: %s", str(e))

    def monitor_files(self, file_paths, hash_algorithm):
        event_handler = FileChangeEventHandler(file_paths, hash_algorithm)
        observer = Observer()
        for file_path in file_paths:
            observer.schedule(event_handler, file_path, recursive=True)
        observer.start()
        try:
            observer.join()
        except KeyboardInterrupt:
            observer.stop()
        observer.join()

    def encrypt_file(self, file_path, encryption_key):
        try:
            # Read the file content
            with open(file_path, 'rb') as file:
                file_content = file.read()

            # Generate a random initialization vector (IV)
            iv = os.urandom(self.IV_SIZE)

            # Create the cipher with AES-256 CBC mode
            cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv), backend=default_backend())

            # Encrypt the file content
            encryptor = cipher.encryptor()
            encrypted_content = encryptor.update(file_content) + encryptor.finalize()

            # Write the encrypted content to a new file
            encrypted_file_path = file_path + '.enc'
            with open(encrypted_file_path, 'wb') as encrypted_file:
                encrypted_file.write(iv + encrypted_content)

            logger.info(f"File encrypted and saved as {encrypted_file_path}")

        except Exception as e:
            logger.exception("Failed to encrypt the file: %s", str(e))

    def decrypt_file(self, file_path, encryption_key):
        try:
            # Read the encrypted file content
            with open(file_path, 'rb') as file:
                encrypted_content = file.read()

            # Extract the initialization vector (IV)
            iv = encrypted_content[:self.IV_SIZE]

            # Create the cipher with AES-256 CBC mode
            cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv), backend=default_backend())

            # Decrypt the file content
            decryptor = cipher.decryptor()
            decrypted_content = decryptor.update(encrypted_content[self.IV_SIZE:]) + decryptor.finalize()

            # Write the decrypted content to a new file
            decrypted_file_path = file_path + '.dec'
            with open(decrypted_file_path, 'wb') as decrypted_file:
                decrypted_file.write(decrypted_content)

            logger.info(f"File decrypted and saved as {decrypted_file_path}")

        except Exception as e:
            logger.exception("Failed to decrypt the file: %s", str(e))

    def sign_file(self, file_path, private_key_path):
        try:
            # Read the file content
            with open(file_path, 'rb') as file:
                file_content = file.read()

            # Load the private key
            with open(private_key_path, 'rb') as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend()
                )

            # Generate a digest of the file content
            digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
            digest.update(file_content)
            file_digest = digest.finalize()

            # Sign the digest using the private key
            signature = private_key.sign(
                file_digest,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            # Save the signature along with the file
            signature_file_path = file_path + '.sig'
            with open(signature_file_path, 'wb') as signature_file:
                signature_file.write(signature)

            logger.info(f"File signed and signature saved as {signature_file_path}")

        except Exception as e:
            logger.exception("Failed to sign the file: %s", str(e))

    def verify_signature(self, file_path, public_key_path):
        try:
            # Read the file content
            with open(file_path, 'rb') as file:
                file_content = file.read()

            # Read the signature
            signature_file_path = file_path + '.sig'
            with open(signature_file_path, 'rb') as signature_file:
                signature = signature_file.read()

            # Load the public key
            with open(public_key_path, 'rb') as key_file:
                public_key = serialization.load_pem_public_key(
                    key_file.read(),
                    backend=default_backend()
                )

            # Generate a digest of the file content
            digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
            digest.update(file_content)
            file_digest = digest.finalize()

            # Verify the signature using the public key
            public_key.verify(
                signature,
                file_digest,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            logger.info("Signature verification successful")

        except Exception as e:
            logger.exception("Failed to verify the signature: %s", str(e))

    def encrypt_file_with_google_kms(self, file_path, key_name, key_version):
        try:
            # Read the file content
            with open(file_path, 'rb') as file:
                file_content = file.read()

            # Encrypt the file content using Google Cloud KMS
            encrypted_content = self.google_kms_client.encrypt(key_name, key_version, file_content)

            # Write the encrypted content to a new file
            encrypted_file_path = file_path + '.enc'
            with open(encrypted_file_path, 'wb') as encrypted_file:
                encrypted_file.write(encrypted_content)

            logger.info(f"File encrypted using Google Cloud KMS and saved as {encrypted_file_path}")

        except Exception as e:
            logger.exception("Failed to encrypt the file using Google Cloud KMS: %s", str(e))

    def decrypt_file_with_google_kms(self, file_path, key_name, key_version):
        try:
            # Read the encrypted file content
            with open(file_path, 'rb') as file:
                encrypted_content = file.read()

            # Decrypt the file content using Google Cloud KMS
            decrypted_content = self.google_kms_client.decrypt(key_name, key_version, encrypted_content)

            # Write the decrypted content to a new file
            decrypted_file_path = file_path + '.dec'
            with open(decrypted_file_path, 'wb') as decrypted_file:
                decrypted_file.write(decrypted_content)

            logger.info(f"File decrypted using Google Cloud KMS and saved as {decrypted_file_path}")

        except Exception as e:
            logger.exception("Failed to decrypt the file using Google Cloud KMS: %s", str(e))

    def encrypt_file_with_azure_key_vault(self, file_path, key_name):
        try:
            # Read the file content
            with open(file_path, 'rb') as file:
                file_content = file.read()

            # Encrypt the file content using Azure Key Vault
            encrypted_content = self.azure_kms_client.encrypt(key_name, file_content)

            # Write the encrypted content to a new file
            encrypted_file_path = file_path + '.enc'
            with open(encrypted_file_path, 'wb') as encrypted_file:
                encrypted_file.write(encrypted_content)

            logger.info(f"File encrypted using Azure Key Vault and saved as {encrypted_file_path}")

        except Exception as e:
            logger.exception("Failed to encrypt the file using Azure Key Vault: %s", str(e))

    def decrypt_file_with_azure_key_vault(self, file_path, key_name):
        try:
            # Read the encrypted file content
            with open(file_path, 'rb') as file:
                encrypted_content = file.read()

            # Decrypt the file content using Azure Key Vault
            decrypted_content = self.azure_kms_client.decrypt(key_name, encrypted_content)

            # Write the decrypted content to a new file
            decrypted_file_path = file_path + '.dec'
            with open(decrypted_file_path, 'wb') as decrypted_file:
                decrypted_file.write(decrypted_content)

            logger.info(f"File decrypted using Azure Key Vault and saved as {decrypted_file_path}")

        except Exception as e:
            logger.exception("Failed to decrypt the file using Azure Key Vault: %s", str(e))

    def encrypt_file_with_aws_kms(self, file_path, key_id):
        try:
            # Read the file content
            with open(file_path, 'rb') as file:
                file_content = file.read()

            # Encrypt the file content using AWS KMS
            encrypted_content = self.aws_kms_client.encrypt(key_id, file_content)

            # Write the encrypted content to a new file
            encrypted_file_path = file_path + '.enc'
            with open(encrypted_file_path, 'wb') as encrypted_file:
                encrypted_file.write(encrypted_content)

            logger.info(f"File encrypted using AWS KMS and saved as {encrypted_file_path}")

        except Exception as e:
            logger.exception("Failed to encrypt the file using AWS KMS: %s", str(e))

    def decrypt_file_with_aws_kms(self, file_path, key_id):
        try:
            # Read the encrypted file content
            with open(file_path, 'rb') as file:
                encrypted_content = file.read()

            # Decrypt the file content using AWS KMS
            decrypted_content = self.aws_kms_client.decrypt(key_id, encrypted_content)

            # Write the decrypted content to a new file
            decrypted_file_path = file_path + '.dec'
            with open(decrypted_file_path, 'wb') as decrypted_file:
                decrypted_file.write(decrypted_content)

            logger.info(f"File decrypted using AWS KMS and saved as {decrypted_file_path}")

        except Exception as e:
            logger.exception("Failed to decrypt the file using AWS KMS: %s", str(e))

def run(self, input_path, hash_algorithm, exclude_list_file, store_hashes_file, tpm_enabled, excluded_filetypes=None):
    try:
        self.validate_input_path(input_path)
        self.validate_file_path(exclude_list_file)
        self.validate_file_path(store_hashes_file)

        # Load the exclusion list
        exclusion_list = self.load_exclusion_list(exclude_list_file)

        # Load the stored hashes
        self.load_stored_hashes(store_hashes_file)

        # Get the file paths
        if os.path.isfile(input_path):
            file_paths = [input_path]
        else:
            file_paths = self.get_files_in_directory(input_path, excluded_filetypes)

        # Exclude files from the results
        file_paths = self.exclude_files_from_results(file_paths, exclusion_list)

        # Perform integrity checks
        self.parallel_integrity_checks(file_paths, hash_algorithm)

        # Store hashes in TPM if enabled
        if tpm_enabled:
            tpm = self.initialize_tpm()
            if tpm is not None:
                self.store_hashes_in_tpm(tpm, self.stored_hashes)

        # Save the stored hashes
        self.save_stored_hashes(store_hashes_file)

    except Exception as e:
        logger.exception("An error occurred: %s", str(e))


class FileChangeEventHandler(FileSystemEventHandler):
    def __init__(self, file_paths, hash_algorithm, google_kms_client=None, azure_kms_client=None, aws_kms_client=None):
        super().__init__()
        self.file_paths = file_paths
        self.hash_algorithm = hash_algorithm
        self.google_kms_client = google_kms_client
        self.azure_kms_client = azure_kms_client
        self.aws_kms_client = aws_kms_client

    def on_modified(self, event):
        if event.is_directory:
            return
        file_path = event.src_path
        if file_path in self.file_paths:
            file_integrity_checker = FileIntegrityChecker(
                self.google_kms_client,
                self.azure_kms_client,
                self.aws_kms_client
            )
            # Check if any of the KMS clients are initialized
            if (
                self.google_kms_client is None
                and self.azure_kms_client is None
                and self.aws_kms_client is None
            ):
                print("Warning: No KMS clients initialized. Integrity check will be performed without encryption.")
            file_integrity_checker.perform_integrity_check(file_path, self.hash_algorithm)

def main():
    parser = argparse.ArgumentParser(description="File Integrity Checker")
    parser.add_argument("input_path", help="File or directory to check for integrity")
    parser.add_argument("-a", "--algorithm", choices=["md5", "sha1", "sha256"], default="sha256", help="Hash algorithm to use (default: sha256)")
    parser.add_argument("-e", "--exclude", default=None, help="File containing a list of files to exclude from integrity checks")
    parser.add_argument("-s", "--store-hashes", default="stored_hashes.json", help="File to store the calculated hashes")
    parser.add_argument("--tpm", action="store_true", help="Enable storing hashes in TPM (Windows only)")
    parser.add_argument("-k", "--kms", choices=["google", "azure", "aws"], default="google", help="Key Management System to use (default: google)")

    args = parser.parse_args()

    # Load KMS information from config.json
    with open('config.json') as config_file:
        config = json.load(config_file)
        project_id = config.get('PROJECT_ID')
        location_id = config.get('LOCATION_ID')
        key_ring_id = config.get('KEY_RING_ID')
        vault_name = config.get('VAULT_NAME')
        client_id = config.get('CLIENT_ID')
        client_secret = config.get('CLIENT_SECRET')

    # Determine which KMS client to use based on the user's selection
    google_kms_client = None
    azure_kms_client = None
    aws_kms_client = None

    if args.kms == "google":
        google_kms_client = google_kms.KeyManagementServiceClient()
    elif args.kms == "azure":
        azure_kms_client = SecretClient(vault_url=f"https://{vault_name}.vault.azure.net/", credential=DefaultAzureCredential())
    elif args.kms == "aws":
        aws_kms_client = boto3.client('kms', region_name=location_id, aws_access_key_id=client_id, aws_secret_access_key=client_secret)

    # Configure logging
    logging.basicConfig(filename='file_integrity.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    logger = logging.getLogger(__name__)

    # Create an instance of FileIntegrityChecker
    file_integrity_checker = FileIntegrityChecker(google_kms_client, azure_kms_client, aws_kms_client)

    # Run the integrity check
    file_integrity_checker.run(args.input_path, args.algorithm, args.exclude, args.store_hashes, tpm_enabled=False)

    # Monitor files for changes
    event_handler = FileChangeEventHandler(file_paths=file_integrity_checker.get_files_in_directory(args.input_path), hash_algorithm=args.algorithm, google_kms_client=google_kms_client, azure_kms_client=azure_kms_client, aws_kms_client=aws_kms_client)
    observer = Observer()
    observer.schedule(event_handler, args.input_path, recursive=True)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

    # Encrypt a file (example)
    encryption_key = b'my_secret_key'
    file_path_to_encrypt = 'path/to/file.txt'
    file_integrity_checker.encrypt_file(file_path_to_encrypt, encryption_key)

    # Decrypt a file (example)
    file_path_to_decrypt = 'path/to/file.txt.enc'
    file_integrity_checker.decrypt_file(file_path_to_decrypt, encryption_key)

def parse_args():
    parser = argparse.ArgumentParser(description='File integrity checker.')
    parser.add_argument('path', help='Path to the file or directory.')
    parser.add_argument('hash_algorithm', help='Hashing algorithm to use.')
    parser.add_argument('store_path', help='Path to the JSON file to store the hashes.')
    parser.add_argument('--exclude', help='Comma-separated list of paths to exclude.')
    parser.add_argument('--ignore_extensions', help='Comma-separated list of file extensions to ignore.')
    args = parser.parse_args()
    if args.ignore_extensions:
        args.ignore_extensions = args.ignore_extensions.split(',')
    return args


if __name__ == "__main__":
    args = parse_args()
    checker = FileIntegrityChecker()
    checker.run(args.path, args.hash_algorithm, args.exclude, args.store_path, tpm_enabled=False)
