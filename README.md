
# Vaultlyn Encryption Vault

Vaultlyn is an Open-Source symmetric encryption vault program made using Python and has a Command-line user interface which can be operated via Menu. 


![Logo](https://firebasestorage.googleapis.com/v0/b/millie-book-cover.appspot.com/o/Vaultlyn%20PNG.png?alt=media&token=1de2988e-ea30-4e5f-acbd-d5ccc1ddcb3d)
[![GPLv3 License](https://img.shields.io/badge/License-GPL%20v3-green.svg)](https://opensource.org/licenses/)

[![GPLv3 License](https://img.shields.io/badge/Join%20us%20on-Discord-blue)](https://discord.gg/j2Yw7mAdRt)

[![portfolio](https://img.shields.io/badge/my_portfolio-000?style=for-the-badge&logo=ko-fi&logoColor=white)](https://sidharthplportfolio.netlify.app)
## Features

- Fast Encryption and Decryption
- Encrypt any files types
- Nominee Logins (Add upto 2 Nominees to your vault)
- Natively supported for both Windows and Linux. Moderation required for MacOS.
- Works offline. (Datas will not be shared to the servers.)
- High Privacy.

## Installation

Install needed libraries to run the Program.
- First Create a virtual environment while running on Windows. Can be run as it is on Linux.
```powershell
    pip install virtualenv
    python<version> -m venv <virtual-environment-name>
    mkdir projectA
    cd projectA
    python3.8 -m venv env
    source env/bin/activate
    env/Scripts/activate.bat //In CMD
    env/Scripts/Activate.ps1 //In Powershel
```

```bash
  pip install cryptography
  pip install keyboard
  pip install pyfiglet
  pip install subprocess
  pip install platform
```

```bash
    //You need to manually configure the Directory for storing the program's data.
    Open the 'vaultlyn.py' file on a Text Editor and change the '/path/to/Directory/'
    to your desired directory for your OS. *Make sure to create
    the 'SFCV_Decrypting_Passcode' folder on your Home folder according to that,
    configure your path on the code.
```
- Now Just run the 'vaultlyn.py' from your console and run the setup on running for the first time. After setup you can start using the credentials which you configured during the setup.
    
## Support

For support, email mailtosidharth.me@gmail.com or join our Discord Server.
