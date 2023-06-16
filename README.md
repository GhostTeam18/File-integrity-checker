<br/>
<p align="center">
  <h3 align="center">File Integrity Checker</h3>

  <p align="center">
    <a href="https://github.com/Ghostteam18/ File-integrity-checker"><strong>Explore the docs »</strong></a>
    <br/>
    <br/>
  </p>
</p>

![Downloads](https://img.shields.io/github/downloads/Ghostteam18/ File-integrity-checker/total) ![Contributors](https://img.shields.io/github/contributors/Ghostteam18/ File-integrity-checker?color=dark-green) ![Issues](https://img.shields.io/github/issues/Ghostteam18/ File-integrity-checker) ![License](https://img.shields.io/github/license/Ghostteam18/ File-integrity-checker) 

## Table Of Contents

* [About the Project](#about-the-project)
* [Built With](#built-with)
* [Getting Started](#getting-started)
  * [Prerequisites](#prerequisites)
  * [Installation](#installation)
* [Usage](#usage)
* [Contributing](#contributing)
* [License](#license)
* [Authors](#authors)
* [Acknowledgements](#acknowledgements)

## About The Project

The File Integrity Checker is a Python script that allows you to perform file integrity checks and monitor files for changes using various hash algorithms. It calculates the hash value of files, compares them with previously stored hashes, and logs audit events indicating the status of each file (e.g., OK or MODIFIED). The script supports exclusion lists, encryption/decryption using different Key Management Systems (KMS), and integration with Trusted Platform Modules (TPM) on Windows. Features

## Built With

Python! google-cloud-kms! azure-identity, azure-keyvault-secrets!

## Getting Started

This is an example of how you may give instructions on setting up your project locally.
To get a local copy up and running follow these simple example steps.

### Prerequisites

Python: The File Integrity Checker is written in Python, so you need to have Python installed on your system. You can download the latest version of Python from the official Python website (https://www.python.org) and follow the installation instructions for your operating system.

Required Python Packages: The File Integrity Checker relies on several external Python packages. You can install these packages using the pip package manager, which is usually installed along with Python. Run the following command in your terminal or command prompt to install the required packages:

sql

pip install watchdog google-cloud-kms azure-identity azure-keyvault-secrets boto3 cryptography

This command will install the necessary packages for file system monitoring, key management services (Google Cloud KMS, Azure Key Vault, AWS KMS), and cryptography.

Configuration File: The File Integrity Checker requires a configuration file named config.json to store the credentials and settings for the key management services. Create a config.json file in the same directory as the script and populate it with the required information for your chosen key management service. Refer to the documentation or examples provided by the respective key management service for the required configuration details.

Example config.json structure for Google Cloud KMS:

json

{
  "PROJECT_ID": "your-project-id",
  "LOCATION_ID": "your-location-id",
  "KEY_RING_ID": "your-key-ring-id",
  "CLIENT_ID": "your-client-id",
  "CLIENT_SECRET": "your-client-secret"
}

Example config.json structure for Azure Key Vault:

json

{
  "VAULT_NAME": "your-vault-name"
}

Example config.json structure for AWS KMS:

json

{
  "LOCATION_ID": "your-location-id",
  "KEY_ID": "your-key-id",
  "CLIENT_ID": "your-client-id",
  "CLIENT_SECRET": "your-client-secret"
}

Replace the placeholder values with your actual credentials and settings.

Trusted Platform Module (TPM) Support (Windows Only): If you plan to use TPM-based storage for hashes, ensure that your Windows system has TPM support enabled. The TPM functionality can be enabled in the system BIOS settings. Refer to your system's documentation or consult the manufacturer for instructions on enabling TPM.

### Installation

To install and set up the File Integrity Checker, follow these steps:

    Clone the Repository: Start by cloning the repository to your local machine. Open a terminal or command prompt and run the following command:

    bash

git clone <repository-url>

Replace <repository-url> with the URL of the repository you want to clone. If you don't have Git installed, you can alternatively download the repository as a ZIP file and extract it to a local directory.

Navigate to the Directory: Change your current directory to the cloned repository directory:

bash

cd file-integrity-checker

Create and Activate a Virtual Environment (Optional): It is recommended to use a virtual environment to isolate the dependencies of the File Integrity Checker. Run the following command to create a new virtual environment:

bash

python -m venv env

Activate the virtual environment:

    For Windows:

    bash

env\Scripts\activate

For macOS and Linux:

bash

    source env/bin/activate

Install Dependencies: With the virtual environment activated (if used), install the required Python dependencies. Run the following command:

pip install -r requirements.txt

This command will install all the necessary packages for the File Integrity Checker.

Configure Key Management Services: Open the config.json file in a text editor and provide the required credentials and settings for your chosen key management service(s). Refer to the "Prerequisites" section for the specific structure of the config.json file.

Usage: The File Integrity Checker can be run using the command-line interface. Execute the script with the desired options and arguments to perform file integrity checks, encryption, and decryption operations. Run the following command to see the available options:

bash

python file_integrity_checker.py --help

Review the available options and usage examples to understand how to run the File Integrity Checker for your specific use case.

Note: The installation steps provided above are for general guidance and may vary depending on your specific environment and requirements.

## Usage

The File Integrity Checker is a command-line tool that allows you to perform file integrity checks, encryption, and decryption operations. Follow the instructions below to use the tool effectively:

    Basic Usage:

    To perform a basic file integrity check, use the following command:

    php

python file_integrity_checker.py <path> <hash_algorithm> <store_path> [--exclude <exclusion_list>] [--ignore_extensions <extensions_list>]

    <path>: Path to the file or directory that you want to check for integrity.
    <hash_algorithm>: Hashing algorithm to use for calculating file hashes. Choose from md5, sha1, or sha256.
    <store_path>: Path to the JSON file where the calculated hashes will be stored.
    [--exclude <exclusion_list>] (optional): Comma-separated list of paths to exclude from the integrity checks.
    [--ignore_extensions <extensions_list>] (optional): Comma-separated list of file extensions to ignore during the checks.

Example usage:

css

python file_integrity_checker.py /path/to/files sha256 integrity_hashes.json --exclude /path/to/exclusions --ignore_extensions .txt,.log

This command will perform file integrity checks on the specified path using the chosen hash algorithm. The results will be stored in the integrity_hashes.json file. The optional parameters allow you to exclude specific files or directories and ignore certain file extensions.

Encryption and Decryption:

The File Integrity Checker also provides functionality for encrypting and decrypting files. You can use the following commands to perform these operations:

    Encrypt a file:

    php

python file_integrity_checker.py encrypt <file_path> <encryption_key>

    <file_path>: Path to the file that you want to encrypt.
    <encryption_key>: Encryption key or passphrase to use for encryption.

Decrypt a file:

php

    python file_integrity_checker.py decrypt <file_path> <encryption_key>

        <file_path>: Path to the encrypted file that you want to decrypt.
        <encryption_key>: Encryption key or passphrase to use for decryption.

Example usage:

bash

python file_integrity_checker.py encrypt /path/to/file.txt my_secret_key
python file_integrity_checker.py decrypt /path/to/file.txt.enc my_secret_key

These commands will encrypt and decrypt the specified file using the provided encryption key.

Monitoring for File Changes:

The File Integrity Checker can monitor files for changes and perform integrity checks whenever a modification occurs. To enable file monitoring, use the following command:

php

python file_integrity_checker.py monitor <path> <hash_algorithm>

    <path>: Path to the directory to monitor for file changes.
    <hash_algorithm>: Hashing algorithm to use for calculating file hashes.

Example usage:

bash

    python file_integrity_checker.py monitor /path/to/files sha256

    This command will start monitoring the specified directory for file changes. Whenever a file is modified, the tool will perform an integrity check using the chosen hash algorithm.

Make sure to replace the <path>, <hash_algorithm>, <store_path>, <exclusion_list>, <extensions_list>, <file_path>, and <encryption_key> with the appropriate values based on your specific use case.

_For more examples, please refer to the [Documentation](https://example.com)_

## Contributing



### Creating A Pull Request

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

Distributed under the MIT License. See [LICENSE](https://github.com/Ghostteam18/ File-integrity-checker/blob/main/LICENSE.md) for more information.

## Authors

* **GhostTeam18** - *Just a someone trying to learn* - [GhostTeam18](https://github.com/GhostTeam18/) - **

## Acknowledgements

* []()
* []()
* []()
