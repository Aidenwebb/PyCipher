Python Cryptography Cipher
==========================

A simple class for encrypting and decrypting a salted string.

Requirements
------------
### Libraries
- cryptography

### Code Example

```python3
#encrypt and decrypt a string
import os
import cipher

if __name__ == '__main__':
    # Generate Salt
    salt = os.urandom(32)
    print("Your salt: {}".format(salt))

    # Get Password from input
    password = input("Type password: ")
    print("Your password: {}".format(password))

    # Create encrypter instance
    encrypter = cipher.Cipher(password, salt)
    print("Your encryption key: {}".format(encrypter.key))

    # Get string from input
    str = input("Type string to encrypt: ")
    print("Your unencrypted string: {}".format(str))

    # Encrypt a string
    encrypted = encrypter.encrypt_string(str)
    print("Your encrypted string: {}".format(encrypted))

    # Decrypt a string
    decrypted = encrypter.decrypt_string(encrypted)
    print("Your decrypted string: {}".format(decrypted))

## Contributors

Project is open for contribution. Pull requests will be reviewed and merged

## License

License & Authors
-----------------
- Author:: Aiden Arnkels-Webb (<aiden@rootwire.co.uk>)

```text
Copyright:: 2016, Rootwire Ltd

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```