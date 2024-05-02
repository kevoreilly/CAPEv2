#!/bin/bash

source venv/bin/activate
python cuckoo.py &

cd web
python manage.py migrate
python manage.py runserver
