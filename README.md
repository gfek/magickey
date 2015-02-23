# MagicKey

Capture the hash of the current logged on user (even if the user has not local administrator privileges).

### Help


              __  __             _      _  __
             |  \/  | __ _  __ _(_) ___| |/ /___ _   _
             | |\/| |/ _` |/ _` | |/ __| ' // _ \ | | |
             | |  | | (_| | (_| | | (__| . \  __/ |_| |
             |_|  |_|\__,_|\__, |_|\___|_|\_\___|\__, |
                           |___/                 |___/

                           George Fekkas
            <g [dot] fekkas [at] encodegroup [dot] com>


usage: magickey.exe [-h] [-v]

The MagicKey is an application for harvesting NTLMv1/NTLMv2 hash (currently Logged On User) without having administrator privileges. Then you can crack the hash. Magic, huh!!!

optional arguments:

  -h, --help     show this help message and exit
  
  -v, --verbose  show loop dance authentication (Type1/Type2/Type3)
  
