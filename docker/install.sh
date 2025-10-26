git clone https://github.com/nbdy/CAPEv2 cape
cd cape

bash extra/yara_installer.sh
bash extra/libvirt_installer.sh

python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -r extra/optional_dependencies.txt
pip install -U flare-floss