#!/bin/bash

for filename in conf/default/*.conf.default conf/default/*.env; do
    dest="conf/${filename#conf/default/}"
    cp -vf "./$filename" "./${dest%.default}"
done
