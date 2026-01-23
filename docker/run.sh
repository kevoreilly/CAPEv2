#!/bin/bash
set -e

cd /cape

# Initialize configs if mounted volume is empty
if [ ! -f "conf/cuckoo.conf" ]; then
    echo "Initializing configuration files..."
    bash conf/copy_configs.sh
fi

# Configure Database connection for Docker environment
mkdir -p conf/cuckoo.conf.d
DB_CONF="conf/cuckoo.conf.d/00_docker_db.conf"
if [ ! -f "$DB_CONF" ]; then
    echo "Creating Docker DB configuration..."
    cat > "$DB_CONF" <<EOF
[database]
connection = postgresql://${POSTGRES_USER:-cape}:${POSTGRES_PASSWORD:-cape}@cape-db:5432/${POSTGRES_DB:-cape}
EOF
fi

cd web
python manage.py migrate
cd ..

python cuckoo.py &
CUCKOO_PID=$!

cd web

: "${WEB_PORT:=8000}"

python manage.py runserver 0.0.0.0:${WEB_PORT}