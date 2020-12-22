### [22.12.2020] Peque edition
* TLS decrypt integration, huge thanks to Hatching team to release their code. WEBGUI integration isn't finished yet, but you already can see https requests there
* Safelists moved from network.py to `data/safelist/{domains,ips}.py`

### [08.12.2020] On demand
* Add uniq submission limitation, can be enabled in `conf/web.conf` to disable the same submission during X hours
* Bingraph, FLARE CAPA, vba2graph on demand
* Added `on_demand` feature.
    * This funcions aim to speedup processing but allow to user to generate parts of analysis that takes some time to finish and not used frequently. Example scripted submissions

### [02.12.2020] CAPE 2.2
* Malduck integration
* Bootrstarp 4.5.3 & font awesome 5
* Statistics
* Tag_tasks - allows you tag your jobs
* self.pefiles: introduced to prcessing/signatures modules, you can get PEFILE object by sha256 self.pefiles.get(sha256)
* Pending page now is much useful and show hashes to easilly spot duplicated
* Submission of file or resubmission will show all the jobs and detection for that file
* [Flare capa](https://github.com/fireeye/capa) integrated under static tab for original binary, procdump and cape (should be enabled in processing.conf), Rules can be pulled from community, but we will leave it community driven to sync them. So you can copy them from https://github.com/fireeye/capa-rules and place under `data/flare-capa`
* More soon ;)

### 16-11-2020
* `utils/cleaners.py` option `--delete-older-than-days` moved to bulk remove 10 in 10, to improve performance and decrease IO

### [31-10-2020] Pre Halloween edition
* [Box-js](https://github.com/kirk-sayre-work/box-js/) integration [docs](https://capev2.readthedocs.io/en/latest/integrations/box-js.html)
* Fixed support for office in x64 VMs

### [22-10-2020]
* cape.py rewrite so it affects `api/tasks/get/config/` so before it was list of configs and it has `cape_name`, now its like `[{malware_family:{config}}]`

### [20-10-2020]
* static config extraction lookup in database before scan file with yara and extract
* resubmit added to CAPE/procdump tabs

### [15-10-2020]
* Huge code unification and cleanup between `submission/views.py` and `api/views.py`
* Improve error messages on bulk submission, for failed samples/hashes
* Physical machinery updated by @hariomenkel, you can [read details in his writeup](https://mariohenkel.medium.com/using-cape-sandbox-and-fog-to-analyze-malware-on-physical-machines-4dda328d4e2c)

### [05-10-2020]
* Static extraction fix, thanks for testing it @nikhilh-20
* Static endpoint now will return config apart of the task id

### [01-10-2020] HacktoberFest edition
* Create zip files in memory (requires pyzipper) instead of using 7z and write them to temp folder
* Simplified parsing of arguments between submission/api views
* Created [docs](https://capev2.readthedocs.io/en/latest/development/current_module_improvement.html) on how to test `Curtain` and `Suricata`
* Static extraction api added
* Curtain module updated
* Code clenup
* Massive useless IO improved, read config once instead of on each file submit

### [14-09-2020]
* Added ability to enable/disable some of 3rd part services for malware detection, like: VirusTotal, ClamAV, Suricata

### [13-09-2020]
* Enable ratelimit on download any file, to avoid scrapping, to change limits, edit: `api.conf` -> `download_file`
* Error message for ratelimit can be configured in `web/web/settings.py`
* Fixed a lot of bugs/typos, thanks Flake8 + GitHub Actions :)

### [11-08-2020]
* Update suricata socket path in processing.conf as in cape2.sh from `/var/run/` to `/tmp/`
* Fix pebble pool restart on timeout
* Zip package reintroduced but it should be only used with option `file=X` when we need side load files

### [23-07-2020]
* Scan extracted macro with yara from macro/CAPE folder

### [11-07-2020]
* [ReadTheDocs](https://capev2.readthedocs.io/en/latest/#)

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
