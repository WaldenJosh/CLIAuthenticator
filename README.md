
# CLIAuthenticator

**CLIAuthenticator** is a Python script that generates Time-based One-Time Passwords (TOTP) codes from a JSON file containing account details and secrets. The script supports encryption and decryption of secrets to keep them secure.

## Features

- Generate TOTP codes for multiple accounts from a JSON file.
- Encrypt and decrypt secrets using a user-provided password.
- Display the remaining validity time for each TOTP code.
- Supports various TOTP settings like time step, digits, and algorithms.
- Dynamically detects TOTP fields in any JSON format.

## Requirements

The following Python packages are required:

- `cryptography`
- `pyotp`

To install the required packages, run:

```bash
pip install -r requirements.txt
```

## Usage

### 1. Generate TOTP Codes

To generate TOTP codes from a JSON file:

```bash
python CLIAuthenticator.py <json_file_path>
```

For example:

```bash
python CLIAuthenticator.py Codes.json
```

### 2. Encrypt the JSON File

To encrypt the secrets in the JSON file:

```bash
python CLIAuthenticator.py encrypt <json_file_path>
```

For example:

```bash
python CLIAuthenticator.py encrypt Codes.json
```

You will be prompted to enter an encryption password and confirm it.

### 3. Decrypt the JSON File

To decrypt the secrets in the JSON file:

```bash
python CLIAuthenticator.py decrypt <json_file_path>
```

For example:

```bash
python CLIAuthenticator.py decrypt Codes.json
```

You will be prompted to enter the decryption password.

## JSON Format

The script dynamically detects TOTP fields within the JSON structure. The JSON file should contain objects with at least the following field:

- `secret`: A base32-encoded string that represents the TOTP seed.

Optional fields include:

- `issuerName`: A string representing the name of the account issuer.
- `userName`: A string representing the user's name or email associated with the account.
- `timeStep`: An integer specifying the time step in seconds (default is 30).
- `digits`: An integer specifying the number of digits in the TOTP code (default is 6).
- `algorithm`: A string specifying the hash algorithm used for TOTP (default is "SHA1").

### Example JSON Structure

The JSON file can be structured in various ways, but here is a generic example:

```json
{
    "accounts": [
        {
            "issuerName": "Example Service",
            "userName": "user@example.com",
            "secret": "BASE32ENCODEDSECRET",
            "timeStep": 30,
            "digits": 6,
            "algorithm": "SHA1"
        },
        {
            "issuerName": "Another Service",
            "secret": "ANOTHERBASE32SECRET"
        }
    ]
}
```

## Notes

- The script dynamically detects TOTP fields and handles different JSON formats.
- Make sure that all secrets are valid base32-encoded strings. The script will normalize and validate these secrets.
- The remaining validity time for each TOTP code will be displayed next to the code itself.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more information.
