# Simple_AES-256
aes.out is Linux OS executable  which is implemented with Crypto++ library for C++.
Usage: When your run aes.out you will be asked to enter file location to be encrypted. Then you have to enter AES encryption mode either CBC or CTR (enter 1 for CBC, 2 for CTR mode). After inputs are taken program encrypts file that was given and creates “<filename>_cipher” file in directory where application was run, which is encryption of file using AES-256 printed {key, iv}. Then it decrypts “<filename>_cipher” to “<filename>_recovered” file which will be stored in directory where program was run.

If you want to build source code, you have to install crypto++ library to your system.
