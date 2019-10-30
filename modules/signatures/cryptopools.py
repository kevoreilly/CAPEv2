from lib.cuckoo.common.abstracts import Signature

class MINERS(Signature):
    name = "cryptopool_domains"
    description = "Connects to crypto curency mining pool"
    severity = 10
    categories = ["miners"]
    authors = ["doomedraven", "bartblaze"]
    minimum = "1.2"
    ttp = ["T1496"]

    pool_domains = [
        "aeon-pool.com",
        "alimabi.cn",
        "backup-pool.com",
        "bohemianpool.com",
        "coinedpool.com",
        "coinmine.pl",
        "cryptity.com",
        "cryptmonero.com",
        "crypto-pool.fr",
        "crypto-pools.org",
        "cryptoescrow.eu",
        "cryptohunger.com",
        "cryptonotepool.org.uk",
        "dwarfpool.com",
        "extremepool.com",
        "extremepool.org",
        "hashinvest.net",
        "iwanttoearn.money",
        "maxcoinpool.com",
        "mine.moneropool.org",
        "minemonero.gq",
        "minercircle.com",
        "mining4all.eu",
        "miningpoolhub.com",
        "mixpools.org",
        "mmcpool.com",
        "monero.crypto-pool.fr",
        "monero.cryptopool.fr",
        "monero.farm",
        "monero.hashvault.pro",
        "monero.lindonpool.win",
        "monero.miners.pro",
        "monero.net",
        "monero.riefly.id",
        "monero.us.to",
        "monerohash.com",
        "monerominers.net",
        "moneroocean.stream",
        "moneropool.com",
        "moneropool.com.br",
        "moneropool.nl",
        "moneropool.org",
        "moriaxmr.com",
        "nonce-pool.com",
        "nut2pools.com",
        "opmoner.com",
        "p2poolcoin.com",
        "pool.cryptoescrow.eu",
        "pool.minergate.com",
        "pool.minexmr.com",
        "pool.xmr.pt",
        "pooldd.com",
        "poolto.be",
        "ppxxmr.com",
        "prohash.net",
        "ratchetmining.com",
        "rocketpool.co.uk",
        "sheepman.mine.bz",
        "supportxmr.com",
        "teracycle.net",
        "usxmrpool.com",
        "viaxmr.com",
        "xminingpool.com",
        "xmr.crypto-pool.fr",
        "xmr.hashinvest",
        "xmr.mypool.online",
        "xmr.nanopool.org",
        "xmr.prohash.net",
        "xmr.suprnova.cc",
        "xmrpool.de",
        "xmrpool.eu",
        "xmrpool.net",
        "xmrpool.xyz",
        "xmr.pool.minergate.com",
    ]

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)

    def run(self):

        if any([domain in self.pool_domains for domain in self.results.get("network", {}).get("domains", [])]):
            self.malfamily = "crypto miner"
            return True
        return False
