rule:
  meta:
    name: hash data using aphash
    namespace: data-manipulation/hashing/aphash
    authors:
      - "@_re_fox"
    scope: function
    mbc:
      - Data::Non-Cryptographic Hash [C0030]
    references:
      - https://www.partow.net/programming/hashfunctions/
  features:
    - and:
      - number: 0xaaaaaaaa
      - instruction:
        - description: hash << 7
        - mnemonic: shl
        - number: 7
      - instruction:
        - description: hash << 11
        - mnemonic: shl
        - number: 11
      - instruction:
        - description: hash >> 5
        - mnemonic: shr
        - number: 5
      - instruction:
        - description: hash >> 3
        - mnemonic: shr
        - number: 3
      - instruction:
        - description: iterator & 1
        - mnemonic: and
        - number: 1
      - characteristic: nzxor
      - characteristic: loop
