#!/bin/bash
set -e

cd /cape

cd web
python manage.py migrate
cd ..

python cuckoo.py &
CUCKOO_PID=$!

cd web

: "${WEB_PORT:=8000}"

python manage.py runserver 0.0.0.0:${WEB_PORT}