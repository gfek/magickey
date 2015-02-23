# MagicKey

During a Cyber Threat Assessment or an Advanced Persistent Threat Readi- ness exercise an initial foothold is established to the internal network through the end user’s workstation. If the current logged on user is a local adminis- trator then the penetration tester is able to retrieve system hashes from the memory using tools such as mimikatz, wce, pwdumpX e.t.c. Let’s imagine that an internal user’s workstation is compromised, however normal user access has been granted (e.g. not as a local administrator). How the penetration tester will retrieve the password of the current logged on user? Social engineering is an potential option, where the penetration tester can upload a malicious appli- cation which will display a fake pop-up login (e.g. e-mail client) in the user’s screen. Then, potentially, the end user will fill the text boxes, username and password respectively. The malware will create a text file with the user’s cre- dentials. In this paper we describe a different technique where a penetration tester is able to capture the hash of the current logged on user (even if the user has not local administrator privileges) through the Window Security Support Provider Interface (SSPI) framework.

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
  
