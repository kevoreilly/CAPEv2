### Consider to use custom configs directory to simplify your life on updates

* Allow custom config dirs that extend the default ones.
* $CAPE_ROOT = /opt/CAPEv2

A new `$CAPE_ROOT/custom/conf/` directory can be used to hold additional
configuration files that extend the ones in the top-level conf
directory. See the custom/README.md for more information.

`.conf.d` (e.g. `$CAPE_ROOT/custom/conf/reporting.conf.d/`) directories may also
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
