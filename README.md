analyzeSSL
==========

Quick script to check SSL configuration of a list of domains using SSL labs api. It's kept intentionally slow (1 host at a time) to avoid abuse to SSLLabs.

Currently this script takes input from a file endpoints.txt, which needs to be present in the same directory as analyzeSSL.py along with accepted_ciphers.txt. The result of this script are a little unstable based on SSLLabs api's performance. 


To do:

1. Have better error handling
2. ~~Remove hardcoded filenames to allow for arguments.~~
3. Proper CSV output
