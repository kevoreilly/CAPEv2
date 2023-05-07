===================
Pattern replacement
===================
* Replace/discard any host/network pattern.


Cleaning Operation system patterns.
===================================
* Enable filtering inside ``custom/conf/processing.conf``::
    * ``behavior`` -> ``replace_patterns``
    * ``CAPE`` -> ``replace_patterns``

* Put your patterns inside of ``data/safelist/replacepatterns.py``

Cleaning Network patterns as IP(s)/Domains.
===============================================
* Enable filtering inside ``custom/conf/processing.conf`` -> ``network`` -> ``dnswhitelist/ipwhitelist``
    * Add all IP(s) and domains to specified files that you want to remove from report into:
        * ``extra/whitelist_domains.txt``
        * ``extra/whitelist_ips.txt``
    * By default we are filtering some of domains already from this list:
        * ``data/safelist/domains.py``
