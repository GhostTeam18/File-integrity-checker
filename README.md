File Integrity Checker

The File Integrity Checker is a Python script that allows you to perform file integrity checks and monitor files for changes using various hash algorithms. It calculates the hash value of files, compares them with previously stored hashes, and logs audit events indicating the status of each file (e.g., OK or MODIFIED). The script supports exclusion lists, encryption/decryption using different Key Management Systems (KMS), and integration with Trusted Platform Modules (TPM) on Windows.
Features

    Calculate and compare file hashes using different hash algorithms (MD5, SHA1, SHA256).
    Exclude specific files or directories from integrity checks using an exclusion list.
    Store calculated hashes in a JSON file for future comparisons.
    Monitor files and log audit events when changes are detected.
    Support for encryption and decryption of files using various KMS providers (Google Cloud KMS, Azure Key Vault, AWS KMS).
    Integration with TPM for storing and retrieving hashes (Windows only).

Installation

    Clone the repository:

    shell

git clone https://github.com/GhostTeam18/file-integrity-checker.git
cd file-integrity-checker

Install the required dependencies:

shell

pip install -r requirements.txt

Set up the configuration file:

    Copy the config.example.json file to config.json.
    Fill in the required information for your KMS providers (Google Cloud KMS, Azure Key Vault, AWS KMS).

Run the script:

shell

    python file_integrity_checker.py <input_path> --algorithm <hash_algorithm> --exclude <exclude_list_file> --store-hashes <store_hashes_file> [--tpm] [--kms <kms_provider>]

        <input_path>: The file or directory to check for integrity.
        <hash_algorithm>: The hash algorithm to use (MD5, SHA1, SHA256). Default: SHA256.
        <exclude_list_file>: Optional. A file containing a list of files to exclude from integrity checks.
        <store_hashes_file>: The file to store the calculated hashes.
        --tpm: Optional. Enable storing hashes in TPM (Windows only).
        --kms <kms_provider>: Optional. Specify the Key Management System to use (google, azure, aws). Default: google.

Usage
Basic Usage

To perform a file integrity check on a file or directory, use the following command:

shell

python file_integrity_checker.py <input_path> --algorithm <hash_algorithm> --store-hashes <store_hashes_file>

    <input_path>: The file or directory to check for integrity.
    <hash_algorithm>: The hash algorithm to use (MD5, SHA1, SHA256).
    <store_hashes_file>: The file to store the calculated hashes.

Exclusion List

To exclude specific files or directories from the integrity check, create a file containing a list of paths to exclude and use the --exclude option:

shell

python file_integrity_checker.py <input_path> --algorithm <hash_algorithm> --store-hashes <store_hashes_file> --exclude <exclude_list_file>

    <exclude_list_file>: A file containing a list of files or directories to exclude from integrity checks.

TPM Integration

If you are using Windows and want to store and retrieve hashes from a Trusted Platform Module (TPM), use the --tpm option:

shell

python file_integrity_checker.py <input_path> --algorithm <hash_algorithm> --store-hashes <store_hashes_file> --tpm

Encryption and Decryption

To encrypt or decrypt files using different KMS providers, specify the KMS provider using the --kms option:

shell

python file_integrity_checker.py <input_path> --algorithm <hash_algorithm> --store-hashes <store_hashes_file> --kms <kms_provider>

    <kms_provider>: The Key Management System to use (google, azure, aws).

Monitoring Files

To monitor files for changes and perform integrity checks in real-time, run the script without any additional arguments:

shell

python file_integrity_checker.py

This will start monitoring the files specified in the input_path for changes and perform integrity checks whenever a change is detected.
Configuration

The config.json file contains the configuration settings for the KMS providers. Fill in the required information for each provider:

    Google Cloud KMS:
        PROJECT_ID: The ID of your Google Cloud project.
        LOCATION_ID: The location of the key ring within your project.
        KEY_RING_ID: The ID of the key ring.
    Azure Key Vault:
        VAULT_NAME: The name of your Azure Key Vault.
    AWS KMS:
        LOCATION_ID: The AWS region ID where the KMS key is located.
        KEY_ID: The ID of the KMS key.

License

This project is licensed under the MIT License. See the LICENSE file for details.
Contributing

Contributions are welcome!
Acknowledgments

    The File Integrity Checker script was inspired by the need for a reliable and efficient way to perform file integrity checks in various environments. I also just wanted to try my hand at it :)
    Special thanks to the authors and contributors of the libraries and frameworks used in this project.
