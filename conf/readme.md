### Simplify your life

* Community tag before module section means that module is done/maintained by community, not core dev.

* Do NOT edit files with this name schema `<name>.conf.default` it will contain the same as repo config and in case if new field is added you don't need to update your config
* Now you can use any of the following path to edit your configuration:
    * `<name>.conf`
    * `<name>.conf.d`
    * `custom/conf/<name>.conf` # backward friendly
    * `custom/conf/<name>.conf.d/*` # backward friendly

* `$CAPE_ROOT = /opt/CAPEv2`

`.conf.d` (e.g. `$CAPE_ROOT/conf/reporting.conf.d/`) directories may also
be used to store additional configuration.

In addition, for `Config()` objects, only read the files once, so that if,
say, `Config("processing")` is created in multiple places, they'll both
refer to the same object and the conf files would only be read once.

A new `AnalysisConfig()` class was created to separate the distinction
between these types of "singleton" Config objects that can read from
multiple directories versus ones that just read from an analysis.conf
(or some other single file).

Allow environment variables to be referenced in config files.
Allow config files to use values that are formatted like
`%(ENV:SOME_ENVIRONMENT_VARIABLE)s`. In certain deployment strategies,
this makes it easier to deal with secrets since they don't need to be
stored on disk anywhere.

* Don't include the envvars in `Config.get()`.

`Config.get()` should only return the items that were actually in the
config file.

By: [Tommy Beadle](https://github.com/tbeadle) -> [commit](https://github.com/kevoreilly/CAPEv2/commit/e217139ff6cd1ad8f8e74626af990c1913653d21)

### Extras - Mostly for devs only
When jumping between branches is become hard to keep config syncronized.
So as solution we introduce `CAPE_CD` aka `CAPE Config Directory` env variable.

* Example:
    * CAPE_CD=/opt/CAPEv2_conf poetry run python cuckoo.py
    * CAPE_CD=/opt/CAPEv2_conf poetry run python utils/process.py
    * CAPE_CD=/opt/CAPEv2_conf poetry run python manage.py runserver 0.0.0.0:8000
