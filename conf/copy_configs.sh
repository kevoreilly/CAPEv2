#!/bin/bash

for filename in conf/default/*.{conf,env}.default; do
    dest="conf/${filename#conf/default/}"
    cp -vf "./$filename" "./${dest%.default}"
done
