Real generator output used by `tests/test_shellcode_check.py` (zlib-compressed, base64), built from
tiny header-only test PEs (no functional payload):

- `donut_*.b64`: Donut 1.1 (`donut-shellcode` Python module). Trimmed to the instance plus the
  first 64 bytes of the loader stub, which is everything the identification reads.
  - `donut_x64_enc`: x64, Chaskey-encrypted instance, embedded EXE
  - `donut_x86_plain`: x86, no encryption, embedded EXE
  - `donut_x84_aplib`: x86+x64, encrypted, aPLib-compressed EXE
  - `donut_http`: x64, encrypted, module staged from `http://10.0.0.5/files/<random>` (not a real server)
- `srdi_*.b64`: sRDI `ConvertToShellcode` (monoxgas/sRDI, Python), export hash 0x30627745,
  user data `run=1`, flags clear header + obfuscate imports.
- `msf_encoders.b64`: JSON of `{name: {blob, payload}}` hex pairs. Metasploit (msfvenom) encoder
  output for x64/xor, xor_dynamic (x86/x64), zutto_dekiru, call4_dword_xor, fnstenv_mov, countdown,
  jmp_call_additive, alpha_mixed and alpha_upper, plus a two-encoder chain, each wrapping the
  test suite's reverse-TCP style payloads. Built with Python ports of the encoders
  (modules/encoders/x86|x64 and rex-encoder alpha2, including the Rex counter prefixes); every
  vector was checked by running its real decoder stub in unicorn, which must rebuild the payload.
