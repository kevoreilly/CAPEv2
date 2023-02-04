from lib.cuckoo.common.abstracts import Signature


class RansomwareExtensions(Signature):
    name = "ransomware_extensions"
    description = "Appends known ransomware file extensions to files that have been encrypted"
    severity = 3
    families = []
    categories = ["ransomware"]
    authors = ["Kevin Ross", "bartblaze"]
    minimum = "1.2"
    ttps = ["T1486"]  # MITRE v6,7,8
    mbcs = ["OB0008", "E1486"]
    mbcs += ["OC0001", "C0015"]  # micro-behaviour

    def run(self):
        indicators = [
            (".*\.toxcrypt$", ["ToxCrypt"]),
            (".*\.hydracrypt_ID_[a-z0-9]{8}$", ["HydraCrypt"]),
            (".*\.hydracrypttmp_ID_[a-z0-9]{8}$", ["HydraCrypt"]),
            (".*\.locked$", ["Locked"]),
            (".*\.cerber$", ["Cerber"]),
            (".*\.cerber2$", ["Cerber"]),
            (".*\.cerber3$", ["Cerber"]),
            (".*\.encrypt$", ["multi-family"]),
            (".*\.R5A$", ["7ev3n"]),
            (".*\.R4A$", ["7ev3n"]),
            (".*\.herbst$", ["Herbst"]),
            (".*\.CrySiS$", ["Crysis"]),
            (".*\.bart\.zip$", ["Bart"]),
            (".*\.crypt$", ["CryptXXX"]),
            (".*\.crypz$", ["CryptXXX"]),
            (".*\.cryp1$", ["CryptXXX"]),
            (".*\.[0-9A-F]{32}\.[0-9A-F]{5}$", ["CryptXXX"]),
            (".*\.id_[^\/]*\.scl$", ["CryptFile2"]),
            (".*\.id_[^\/]*\.rscl$", ["CryptFile2"]),
            (".*\.razy$", ["Razy"]),
            (".*\.Venus(f|p)$", ["VenusLocker"]),
            (".*\.fs0ciety$", ["Fsociety"]),
            (".*\.cry$", ["CryLocker"]),
            (".*\.locklock$", ["LockLock"]),
            (".*\.fantom$", ["Fantom"]),
            (".*_nullbyte$", ["Nullbyte"]),
            (".*\.purge$", ["Globe"]),
            (".*\.globe$", ["Globe"]),
            (".*\.raid10$", ["Globe"]),
            (".*\.lovewindows$", ["Globe"]),
            (".*\.domino$", ["Domino"]),
            (".*\.wflx$", ["WildFire-Locker"]),
            (".*\.locky$", ["Locky"]),
            (".*\.zepto$", ["Locky"]),
            (".*\.odin$", ["Locky"]),
            (".*\.shit$", ["Locky"]),
            (".*\.thor$", ["Locky"]),
            (".*\.aesir$", ["Locky"]),
            (".*\.zzzzz$", ["Locky"]),
            (".*\.osiris$", ["Locky"]),
            (".*\.locked$", ["multi-family"]),
            (".*\.encrypted$", ["multi-family"]),
            (".*dxxd$", ["DXXD"]),
            (".*\.~HL[A-Z0-9]{5}$", ["HadesLocker"]),
            (".*\.exotic$", ["Exotic"]),
            (".*\.k0stya$", ["Kostya"]),
            (".*\.1txt$", ["Enigma"]),
            (".*\.0x5bm$", ["Nuke"]),
            (".*\.nuclear55$", ["Nuke"]),
            (".*\.comrade$", ["Comrade-Circle"]),
            (".*\.rip$", ["KillerLocker"]),
            (".*\.adk$", ["AngryDuck"]),
            (".*\.lock93$", ["Lock93"]),
            (".*\.Alcatraz$", ["Alcatraz-Locker"]),
            (".*\.dCrypt$", ["DummyLocker"]),
            # (".*\.enc$", ["encryptJJS"]),
            (".*\.rnsmwr$", ["Gremit"]),
            (".*\.da_vinci_code$", ["Troldesh"]),
            (".*\.magic_software_syndicate$", ["Troldesh"]),
            (".*\.no_more_ransom$", ["Troldesh"]),
            (".*_luck$", ["CryptoLuck"]),
            (".*\.CHIP$", ["CHIP"]),
            (".*\.KRAB$", ["GandCrab"]),
            (".*\.DALE$", ["CHIP"]),
            (".*\.sexy$", ["PayDay"]),
            (".*\.kraken$", ["Kraken"]),
            (".*\.lesli$", ["CryptoMix"]),
            (".*\.sage$", ["Sage"]),
            (".*\.CRYPTOSHIELD$", ["CryptoShield"]),
            (".*\.serpent$", ["Serpent"]),
            (".*\.REVENGE$", ["Revenge"]),
            (".*\.RYK$", ["Ryuk"]),
            (".*\.FTCODE$", ["FTCode"]),
            (".*\.Lazarus$", ["Ouroboros"]),
            (".*\.Lazarus+$", ["Ouroboros"]),
            (".*\.KRONOS$", ["Ouroboros"]),
            (".*\.Yatron$", ["Yatron"]),
            (".*\.HCY$", ["HildaCrypt"]),
            (".*\.guarded$", ["GarrantyDecrypt"]),
            (".*\.lilocked$", ["Lilocked"]),
            (".*\.ragnarok_cry$", ["Ragnarok"]),
            (".*\.ragnarok$", ["Ragnarok"]),
            (".*\.ragnar_[A-Z0-9]{8}$", ["RagnarLocker"]),
            (".*\.key$", ["PwndLocker"]),
            (".*\.pwnd$", ["PwndLocker"]),
            (".*\.pr[o0]L[o0]ck$", ["ProLock"]),
            (".*\.abcd$", ["LockBit"]),
            (".*\.lockbit$", ["LockBit"]),
            (".*\.corona-lock", ["CovidRansomware"]),
            (".*\.thanos$", ["Tycoon"]),
            (".*\.grinch$", ["Tycoon"]),
            (".*\.redrum$", ["Tycoon"]),
            (".*\.*wasted$", ["WastedLocker"]),
            (".*\.vhd$", ["VHD"]),
            (".*\.ragn@r_[A-Z0-9]{8}$", ["RagnarLocker"]),
            (".*\.WannaCash$", ["WannaCash"]),
            (".*\.avdn$", ["Avaddon"]),
            # Appends additional email and/or extension after .mailto
            (".*\.mailto", ["Netwalker-Mailto"]),
            (".*\.GNNCRY$", ["GonnaCry"]),
            (".*\.XONIF$", ["Fonix"]),
            (".*\.NEFILIM$", ["Nefilim"]),
            (".*\.NEPHILIM$", ["Nefilim"]),
            (".*\.NEF1LIM$", ["Nefilim"]),
            (".*\.pandemic$", ["Pandemic"]),
            (".*\.ROGER$", ["ROGER"]),
            (".*\.coin$", ["Jackpot"]),
            (".*\.[[a-z0-9]{8}-[a-z0-9]{8}]$", ["Cryakl-CryLock"]),
            (".*\.crypted$", ["Hakbit-Thanos"]),
            (".*\.tx_locked$", ["ThunderX"]),
            (".*\.[A-Z0-9]{64}$", ["SunCrypt"]),
            (".*\.CONTI$", ["Conti"]),
            (".*\.TJODT", ["CONTI"]),
            (".*\.ReadManual.[A-Z0-9]{8}", ["MountLocker"]),
            (".*\.pysa$", ["PYSA"]),
            (".*\.__NIST_[A-Z0-9]{4}__$", ["Babuk"]),
            (".*\.phoenix$", ["PhoenixCryptoLocker"]),
            (".*\.blackbyte$", ["BlackByte"]),
        ]

        for indicator in indicators:
            results = self.check_write_file(pattern=indicator[0], regex=True, all=True)
            if results and len(results) > 15:
                if indicator[1]:
                    self.families = indicator[1]
                    self.description = (
                        "Appends a known %s ransomware file extension to " "files that have been encrypted" % "/".join(indicator[1])
                    )
                return True

        return False
