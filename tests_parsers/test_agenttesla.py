from contextlib import suppress

from modules.processing.parsers.CAPE.AgentTesla import extract_config

HAVE_MACO = False
with suppress(ImportError):
    from modules.processing.parsers.MACO.AgentTesla import convert_to_MACO

    HAVE_MACO = True


def test_agenttesla():
    # AgentTeslaV5
    with open("tests/data/malware/893f4dc8f8a1dcee05a0840988cf90bc93c1cda5b414f35a6adb5e9f40678ce9", "rb") as data:
        conf = extract_config(data.read())
        assert conf == {
            "Protocol": "SMTP",
            "C2": "mail.guestequipment.com.au",
            "Username": "sendlog@guestequipment.com.au",
            "Password": "Clone89!",
            "EmailTo": "info@marethon.com",
            "Persistence_Filename": "newfile.exe",
            "ExternalIPCheckServices": ["http://ip-api.com/line/?fields=hosting"],
        }

        if HAVE_MACO:
            assert convert_to_MACO(conf).model_dump(exclude_defaults=True, exclude_none=True) == {
                "family": "AgentTesla",
                "other": {
                    "Protocol": "SMTP",
                    "C2": "mail.guestequipment.com.au",
                    "Username": "sendlog@guestequipment.com.au",
                    "Password": "Clone89!",
                    "EmailTo": "info@marethon.com",
                    "Persistence_Filename": "newfile.exe",
                    "ExternalIPCheckServices": ["http://ip-api.com/line/?fields=hosting"],
                },
                "smtp": [
                    {
                        "username": "sendlog@guestequipment.com.au",
                        "password": "Clone89!",
                        "hostname": "mail.guestequipment.com.au",
                        "mail_to": ["info@marethon.com"],
                        "usage": "c2",
                    }
                ],
                "http": [{"uri": "http://ip-api.com/line/?fields=hosting", "usage": "other"}],
                "paths": [{"path": "newfile.exe", "usage": "storage"}],
            }
