### [24-06-2020]
* Show url from where file was downloaded when using Download'n'Exec
* Zip package is depricate as it doesn't support AES etc, to upload with side files use file=X and submit in zip archive, for rest you have [sflock](https://github.com/doomedraven/sflock) <3

### [18-06-2020]
* Restore original dump file, don't dump inmediatelly
* CAPE tab now also loaded via ajax request

### [11-06-2020]
* Extended api search changed, now instead of return only ids, return some basic info, as detection, etc

### [31-05-2020]
* Rewrite /api/ ratelimit implementation to allow unlimited api for existing users([htpasswd](https://httpd.apache.org/docs/2.4/programs/htpasswd.html)), just set username and password as get/post arguments

### [17-05-2020]
* [XLMMacroDeobfuscator](https://github.com/DissectMalware/XLMMacroDeobfuscator) from @DissectMalware integrated
* Yara now compiled once at processing start or reprocessing

### [15-05-2020]
* pyattck upgrade to >= 2.0.2
* moved many files from `/data/` to `community` -> `python3 utils/community.py -h`

### [07-05-2020]
* Behavior data/tab is now loaded via ajax request, to speedup webgui

### [06-05-2020]
* Add parent sample details to analysis
* Add Yara author to webgui, useful when yara name overlap with private yara

### [18-04-2020]
* All not core yara moved to community repo

### [17-04-2020]
* Dark theme is default now, to set old one just do
    * Backup current: `cp /opt/CAPEv2/web/templates/header.html /opt/CAPEv2/web/templates/header-dark.html`
    * Set old theme: `cp /opt/CAPEv2/web/templates/header-light.html /opt/CAPEv2/web/templates/header.html`

### [13-04-2020]
* TLP implemented for analysis, thanks @enzok

### [30-03-2020]
* /configdownload/ is moved to /api/tasks/get/config/<task_id>/ or /api/tasks/get/config/<task_id>/Family/
* Anti-api-spamming feature in monitor
* webgui optimizations(mongo queries improved a lot), thanks [MongoDB university](https://university.mongodb.com) for free cources :)

### [28-03-2020]
* CAPE 2.1 ;)
* A lot of small bug fixes, code cleanup, gui fixes, and monitor improvements
* Now insted if "None matched" we just hide field
* All VMs now are disabled on submission you need to enable it in web.conf
* To submit ZIP file for analisis you need to specify zip package, if no it will be extracted

### [24-03-2020]
* Big update of suricata name extraction/detection
* malscore now is off by default, can be enabled in conf/reporting.conf
* MalFamily renamed to detections

### [12-03-2020]
* community.py reintroduced to simplify everything
    * now all signatures and not core modules are moved to specific repo, please see `python3 utils/community.py -h`

### [29-02-2020]
* SIGHUP handling to stop submitting tasks and stop cuckoo.py, useful for when you need to reload it without breaking running jobs
    * `ps aux|grep "python3 cuckoo.py"|cut -d" " -f 5| xargs kill -1`

### [22-01-2020]
* Add qemu.py with support for x64/x86/MIPS/MIPSEL/ARM/ARMWRT/ARM64/PowerPC/PowerPC64/Sparc/Sparc64
* Basic linux integration is done thanks to @enzok

### [17-01-2020]
* Bson data compression to remove api spamming, [details](http://security.neurolabs.club/2019/12/inline-loop-detection-for-compressing.html), thanks @mabj
* Many bug fixes in cleaners.py, thanks @Enzok

### [14-01-2020]
* Fix local_settings
* move all in 1 dlls, example option to capemon: combo=1,extraction=1,injection=1,compression=1
* Fix ratelimit enabled/disabled in /api/
* Agent now by default set outout to StringIO to make it works with pythonw without extra args

### [08-01-2020]
* Screenshot deduplicacion algorithm is configurable now and default set to ahash, pr #10, thanks @wmetcalf
* Fixed pythonw compability problem, pr #7, thanks @wmetcalf
* Pillow 7 compatible, pr #9, thanks @wmetcalf
* Upgrade ClamAV support, pr #11, thanks @wmetcalf
* All cleaners from cuckoo.py and some from utils folder are moved to unique file utils/cleaners.py, see, -h @doomedraven
* distributed CAPE documentation updated
* m2crypto+swig replaced with cryptography library

### [25-12-2019]
* CAPEv2 is Python3 based
* Django 3 tested
* [ASGI support - async "wsgi"](https://docs.djangoproject.com/en/3.0/howto/deployment/asgi/)
* All found memleaks fixed
* A lot of code improved and bug fixed
* Malware parsers/extractors moved to use upstream libraries instead of include them to the project, to simplify maintaining and code bug fixes
* User experience improved
* Still might contain some bugs, so please let us know if you see any
* Thanks NaxoneZ for all your bug reports and hard testing <3
