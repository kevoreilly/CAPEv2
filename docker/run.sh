source venv/bin/activate
python cuckoo.py &

cd web

: "${WEB_PORT:=8000}"

python manage.py migrate
python manage.py runserver 0.0.0.0:${WEB_PORT}