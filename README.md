## Input:
Contains the outpoint:
* 32 byte prev tx hash (LE)
* 4 byte index (LE)
ScriptSig:
1. Stack Script (Signature)
  * 32 byte r
  * 32 byte s
2. Redeem script: 33 byte Signer PubKey hash
  * 1 byte if 
