# Copyright (C) 2015 Kevin Ross, Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class BitcoinWallet(Signature):
    name = "infostealer_bitcoin"
    description = "Attempts to access Bitcoin/ALTCoin wallets"
    severity = 3
    categories = ["infostealer"]
    authors = ["Kevin Ross", "Optiv"]
    minimum = "1.2"
    ttp = ["T1005"]

    def run(self):
        indicators = [
            ".*\\\\wallet\.dat$",
            ".*\\\\Bitcoin\\\\.*",
            ".*\\\\Electrum\\\\.*",
            ".*\\\\MultiBit\\\\.*",
            ".*\\\\Litecoin\\\\.*",
            ".*\\\\Namecoin\\\\.*",
            ".*\\\\Terracoin\\\\.*",
            ".*\\\\PPCoin\\\\.*",
            ".*\\\\Primecoin\\\\.*",
            ".*\\\\Feathercoin\\\\.*",
            ".*\\\\Novacoin\\\\.*",
            ".*\\\\Freicoin\\\\.*",
            ".*\\\\Devcoin\\\\.*",
            ".*\\\\Franko\\\\.*",
            ".*\\\\ProtoShares\\\\.*",
            ".*\\\\Megacoin\\\\.*",
            ".*\\\\Quarkcoin\\\\.*",
            ".*\\\\Worldcoin\\\\.*",
            ".*\\\\Infinitecoin\\\\.*",
            ".*\\\\Ixcoin\\\\.*",
            ".*\\\\Anoncoin\\\\.*",
            ".*\\\\BBQcoin\\\\.*",
            ".*\\\\Digitalcoin\\\\.*",
            ".*\\\\Mincoin\\\\.*",
            ".*\\\\GoldCoin\\ \(GLD\)\\\\.*",
            ".*\\\\Yacoin\\\\.*",
            ".*\\\\Zetacoin\\\\.*",
            ".*\\\\Fastcoin\\\\.*",
            ".*\\\\I0coin\\\\.*",
            ".*\\\\Tagcoin\\\\.*",
            ".*\\\\Bytecoin\\\\.*",
            ".*\\\\Florincoin\\\\.*",
            ".*\\\\Phoenixcoin\\\\.*",
            ".*\\\\Luckycoin\\\\.*",
            ".*\\\\Craftcoin\\\\.*",
            ".*\\\\Junkcoin\\\\.*",
        ]
        found_match = False

        for indicator in indicators:
            file_matches = self.check_file(pattern=indicator, regex=True, all=True)
            if file_matches:
                for match in file_matches:
                    self.data.append({"file" : match})
                    found_match = True
                self.weight += len(file_matches)

        return found_match
