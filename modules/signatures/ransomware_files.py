# Copyright (C) 2015 KillerInstinct, Optiv, Inc. (brad.spengler@optiv.com)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from lib.cuckoo.common.abstracts import Signature

class RansomwareFiles(Signature):
    name = "ransomware_files"
    description = "Creates a known ransomware decryption instruction / key file."
    weight = 3
    severity = 3
    families = []
    categories = ["ransomware"]
    authors = ["KillerInstinct", "bartblaze"]
    minimum = "1.2"
    ttp = ["T1486"]

    def run(self):
        # List of tuples with a regex pattern for the file name and a list of
        # family names correlating to the ransomware. If the family is unknown
        # just use [""].
        file_list = [
            (".*\\\\help_decrypt\.html$", ["CryptoWall"]),
            (".*\\\\decrypt_instruction\.html$", ["CryptoWall"]),
            (".*\\\\help_your_files\.png$", ["CryptoWall"]),
            (".*\\\\decrypt_instructions\.txt$", ["CryptoLocker"]),
            (".*\\\\vault\.(key|txt)$", ["CrypVault"]),
            (".*\\\\!Decrypt-All-Files.*\.(txt|bmp)$", ["CTB-Locker"]),
            (".*\\\\help_restore_files\.txt$", ["TeslaCrypt", "AlphaCrypt"]),
            (".*\\\\help_to_save_files\.(txt|bmp)$", ["TeslaCrypt", "AlphaCrypt"]),
            (".*\\\\recovery_(file|key)\.txt$", ["TeslaCrypt", "AlphaCrypt"]),
            (".*\\\\restore_files_.*\.(txt|html)$", ["TeslaCrypt", "AlphaCrypt"]),
            (".*\\\\howto_restore_files.*\.(txt|html)$", ["TeslaCrypt", "AlphaCrypt"]),
            (".*\\\\+-xxx-HELP-xxx-+.*\.(png|txt|html)$", ["TeslaCrypt", "AlphaCrypt"]),
            (".*\\\\HELP_RECOVER_instructions\+.*\.(txt|html)$", ["TeslaCrypt", "AlphaCrypt"]),
            (".*\\\\YOUR_FILES_ARE_ENCRYPTED\.HTML$", ["Chimera"]),
            (".*\\\\_?how_recover.*\.(txt|html)$", ["TeslaCrypt", "AlphaCrypt"]),
            (".*\\\\cl_data.*\.bak$", ["WinPlock"]),
            (".*\\\\READ\ ME\ FOR\ DECRYPT\.txt$", ["Fakben"]),
            (".*\\\\YOUR_FILES.url$", ["Radamant"]),
            (".*\\\\_How\ to\ decrypt\ LeChiffre\ files\.html$", ["LeChiffre"]),
            (".*\\\\cryptinfo\.txt$", ["DMALocker"]),
            (".*\\\\README_DECRYPT_HYDRA_ID_.*(\.txt|\.jpg)$", ["HydraCrypt"]),
            (".*\\\\_Locky_recover_instructions\.txt$", ["Locky"]),
            (".*\\\\_DECRYPT_INFO_[a-z]{4,6}\.html$", ["Maktub"]),
            (".*\\\\de_crypt_readme\.(html|txt|bmp)$", ["CryptXXX"]),
            (".*\\\\HELP_YOUR_FILES\.(html|txt)$", ["CryptFile2"]),
            (".*\\\\READ_IT\.txt$", ["MMLocker"]),
            (".*\\\\#\ DECRYPT\ MY\ FILES\ #\.(txt|html|vbs)$", ["Cerber"]),
            (".*\\\\!satana!\.txt$", ["Satana"]),
            (".*\\\\HOW_TO_UNLOCK_FILES_README_\([0-9a-f]+\)\.(txt|html|bmp)$", ["WildFire"]),
            (".*\\\\HELP_DECRYPT_YOUR_FILES\.(html|txt)$", ["CryptFile2"]),
            (".*\\\\!!!\ Readme\ For\ Decrypt\ !!!\.txt$", ["MarsJoke"]),
            (".*_HOWDO_text\.(html|bmp)$", ["Locky"]),
            (".*\\\\!!_RECOVERY_instructions_!!\.(html|txt)$", ["Nuke"]),
            (".*\\\\DECRYPT_YOUR_FILES\.HTML$", ["Fantom"]),
            (".*\\\\README_RECOVER_FILES_.*\.(html|txt|png)$", ["HadesLocker"]),
            (".*\\\\README\.hta$", ["Cerber"]),
            (".*\\\\RESTORE-FILES!.*txt$", ["Comrade-Circle"]),
            (".*_WHAT_is\.(html|bmp)$", ["Locky"]),
            (".*\\\\decrypt\ explanations\.html$", ["n1n1n1"]),
            (".*\\\\ransomed\.html$", ["Alcatraz-Locker"]),
            (".*\\\\CHIP_FILES\.txt$", ["CHIP"]),
            (".*\\\\(?:|_\d\-|\-)INSTRUCTION\.(html|bmp)$", ["Locky"]),
            (".*\\\\_README(\.hta|_.*_\.hta)$", ["Cerber"]),
            (".*\\\\DesktopOSIRIS\.(bmp|htm)$", ["Locky"]),
            (".*\\\\OSIRIS\-[a-f0-9]{4}\.htm$", ["Locky"]),
            ("C:\\[a-z]{8}\.tsv$", ["MegaCortex"]),
            ("C:\\!!!_READ_ME_!!!.txt$", ["MegaCortex"]),
            (".*\\\\README_LOCKED\.txt$", ["LockerGoga"]),
            (".*\\\\README-NOW.txt\.txt$", ["LockerGoga"]),
            (".*\\\\!-GET_MY_FILES-!\.txt$", ["Aurora", "Zorro"]),
            (".*\\\\#RECOVERY-PC#\.txt$", ["Aurora", "Zorro"]),
            (".*\\\\@_RESTORE-FILES_@\.txt$", ["Aurora", "Zorro"]),
            (".*\\\\HOW_TO_DECRYPT\.txt$", ["BasilisqueLocker"]),
            (".*\\\\!!!\ YOUR\ FILES\ ARE\ ENCRYPTED\ !!!\.TXT$", ["Buran"]),
            (".*\\\\!!!CHEKYSHKA_DECRYPT_README\.TXT$", ["Chekyshka"]),
            (".*\\\\HOW_TO_BACK_YOUR_FILES\.txt$", ["ChineseRarypt"]),
            (".*\\\\CIopReadMe\.txt$", ["Clop-CryptoMix"]),
            (".*\\\\_HELP_INSTRUCTION\.TXT$", ["CryptoMix"]),
            (".*\\\\!=How_recovery_files=!\.html$", ["Everbe"]),
            (".*\\\\\.FreezedByMagic\.README\.txt$", ["FreeMe"]),
            ("C:\\\\ProgramData\\\.FreezedByMagic.LOG$", ["FreeMe"]),
            (".*\\\\#\ DECRYPT\ MY\ FILES\ #\.txt$", ["GetCrypt"]),
            (".*\\\\RECOVER-FILES\.html$", ["GlobeImposter"]),
            (".*\\\\READ_IT\.html$", ["GlobeImposter"]),
            (".*\\\\Read___ME\.html$", ["GlobeImposter"]),
            (".*\\\\how_to_back_files\.html$", ["GlobeImposter"]),
            (".*\\\\How\ to\ restore\ your\ files\.hta$", ["GlobeImposter"]),
            (".*\\\\#NEW_WAVE\.html$", ["GlobeImposter"]),
            (".*\\\\YOU_FILES_HERE\.html$", ["GlobeImposter"]),
            (".*\\\\#\ instructions-[A-Z0-9]{5}\ #\.(txt|jpg|vbs)$", ["GoldenAxe"]),
            (".*\\\\README_DECRYPT\.txt$", ["Gpgqwerty"]),
            (".*\\\\DECRYPT_INFORMATION\.html$", ["Hermes"]),
            (".*\\\\precist\.html$", ["JoeGo"]),
            (".*\\\\JSWORM-DECRYPT\.(hta|html)$", ["JSWorm"]),
            (".*\\\\READ-ME-NOW\.txt$", ["LockerGoga"]),
            (".*\\\\@Please_Read_Me\.txt$", ["LooCipher"]),
            (".*\\\\!INSTRUCTI0NS!\.TXT$", ["Maoloa"]),
            (".*\\\\DECRYPT-FILES\.(html|txt)$", ["Maze"]),
            (".*\\\\help\ to\ decrypt\.html$", ["MorrisBatchCrypt"]),
            (".*\\\\_Decrypt_Files\.html$", ["Robbinhood"]),
            (".*\\\\_Help_Help_Help\.html$", ["Robbinhood"]),
            (".*\\\\_Help_Important\.html$", ["Robbinhood"]),
            (".*\\\\_Decryption_ReadMe\.html$", ["Robbinhood"]),
            (".*\\\\RyukReadMe\.txt$", ["Ryuk"]),
            ("C:\\[a-z0-9]{6,9}-HOW-TO-DECRYPT\.txt$", ["Sodinokibi","REvil"]),
            ("C:\\[a-z0-9]{6,9}-readme\.txt$", ["Sodinokibi","REvil"]),
            (".*\\\\#NEWRAR_README#\.TXT$", ["VSSDestroy"]),
            (".*\\\\#DECRYPT_MY_FILES#\.txt$", ["Aurora", "Zorro", "Dragon"]),
            (".*\\\\@\ READ\ ME\ TO\ RECOVER\ FILES\ @\.txt", ["Eris"]),
            (".*\\\\[A-Z0-9]{4,9}-MANUAL\.txt", ["GandCrab"]),
            (".*\\\\NEMTY-DECRYPT\.txt$", ["Nemty"]),
            (".*\\\\README-VIAGRA-[A-Za-z0-9]{8}\.HTML$", ["Viagra"]),
            (".*\\\\PLAGUE[0-9]{2}\.txt$", ["Plague"]),
            (".*\\\\READ\ ME\.(hta|TXT)$", ["Scarab-Dharma"]),
            (".*\\\\FIX_Instructions\.(txt|hta)$", ["Relock"]),
            (".*\\\\Readme_now\.txt$", ["Syrk"]),
            (".*\\\\!_Notice_!\.txt$", ["TFlower"]),
            (".*\\\\@Please_Read_Me@\.txt$", ["WannaCry"]),
            (".*\\\\_readme\.txt$", ["Moka"]),
            (".*\\\\#FOX_README#\.rtf$", ["Fox"]),
            (".*\\\\Restore-My-Files\.txt$", ["Goodmen", "LockBit"]),
            (".*\\\\HOW_DECRYPT_FILES\.txt$", ["Estemani"]),
            (".*\\\\[A-Z0-9]{6}-Readme\.txt$", ["Koko", "Mailto"]),
            (".*\\\\#README\.lilocked$", ["Lilocked"]),
            (".*\\\\SGUARD-README\.(txt|TXT)$", ["SGuard"]),
            (".*\\\\RyukReadMe\.html$", ["Ryuk"]),
            (".*\\\\HOW_TO_RECOVER_DATA\.html$", ["MedusaLocker"]),
            (".*\\\\ClopReadMe\.txt$", ["Clop-CryptoMix"]),
            (".*\\\\Fix-Your-Files\.txt$", ["SNAKE"])
        ]

        for ioc in file_list:
            if self.check_write_file(pattern=ioc[0], regex=True):
                if ioc[1] != "":
                    self.families = ioc[1]
                    self.description = ("Creates a known {0} ransomware "
                                        "decryption instruction / key file."
                                        "".format("/".join(ioc[1])))
                return True

        return False
