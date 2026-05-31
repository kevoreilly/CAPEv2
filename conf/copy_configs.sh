#!/bin/bash

for filename in conf/default/*.conf.default conf/default/*.env; do
    cp -vf "./$filename" "./$(echo "$filename" | sed -e 's/.default//g' | sed -e 's/default//g')";
done
