To generate requirements.pip-compile.txt in this folder, you will need a separate python3 (virtual) environment, then you run something like this:

pip-compile --verbose --generate-hashes -o /home/yourusername/workspace/CAPEv2/black_formatter/requirements.pip-compile.txt /home/yourusername/workspace/CAPEv2/black_formatter/requirements.in
