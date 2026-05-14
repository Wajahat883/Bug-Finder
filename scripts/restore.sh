#!/bin/bash
# Bug Finder — MongoDB Restore Script
# Usage: ./scripts/restore.sh [backup-file.gz]
# If no file specified, uses the latest backup from /backups/

set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-/backups}"
MONGO_HOST="${MONGO_HOST:-localhost}"
MONGO_PORT="${MONGO_PORT:-27017}"
MONGO_USER="${MONGO_USER:-bugfinder}"
MONGO_PASSWORD="${MONGO_PASSWORD:-}"
MONGO_DB="${MONGO_DB:-bugfinder}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}╔══════════════════════════════════════════════╗${NC}"
echo -e "${YELLOW}║     Bug Finder — Database Restore Tool       ║${NC}"
echo -e "${YELLOW}╚══════════════════════════════════════════════╝${NC}"
echo ""

# Resolve backup file
if [ -n "${1:-}" ]; then
  BACKUP_FILE="$1"
else
  BACKUP_FILE=$(ls -t "${BACKUP_DIR}"/*.gz 2>/dev/null | head -1 || true)
  if [ -z "$BACKUP_FILE" ]; then
    echo -e "${RED}ERROR: No backup files found in ${BACKUP_DIR}${NC}"
    echo "       Run: docker-compose exec mongo-backup mongodump ..."
    exit 1
  fi
  echo -e "Using latest backup: ${GREEN}${BACKUP_FILE}${NC}"
fi

if [ ! -f "$BACKUP_FILE" ]; then
  echo -e "${RED}ERROR: File not found: ${BACKUP_FILE}${NC}"
  exit 1
fi

FILE_SIZE=$(du -h "$BACKUP_FILE" | cut -f1)
BACKUP_DATE=$(date -r "$BACKUP_FILE" "+%Y-%m-%d %H:%M:%S" 2>/dev/null || stat -c "%y" "$BACKUP_FILE" | cut -d'.' -f1)

echo ""
echo "  Backup file : $BACKUP_FILE"
echo "  File size   : $FILE_SIZE"
echo "  Created     : $BACKUP_DATE"
echo "  Target DB   : $MONGO_DB @ $MONGO_HOST:$MONGO_PORT"
echo ""
echo -e "${RED}WARNING: This will OVERWRITE the current database!${NC}"
read -p "Type 'yes' to proceed: " CONFIRM
if [ "$CONFIRM" != "yes" ]; then
  echo "Aborted."
  exit 0
fi

START_TIME=$(date +%s)

# Decompress if needed
EXTRACT_DIR=$(mktemp -d)
trap "rm -rf $EXTRACT_DIR" EXIT

echo ""
echo "Extracting backup..."
tar -xzf "$BACKUP_FILE" -C "$EXTRACT_DIR"

# Build auth args
AUTH_ARGS=""
if [ -n "$MONGO_PASSWORD" ]; then
  AUTH_ARGS="--username=$MONGO_USER --password=$MONGO_PASSWORD --authenticationDatabase=admin"
fi

echo "Restoring database..."
mongorestore \
  --host="$MONGO_HOST" \
  --port="$MONGO_PORT" \
  $AUTH_ARGS \
  --db="$MONGO_DB" \
  --drop \
  "$EXTRACT_DIR/$MONGO_DB" \
  --quiet

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

echo ""
echo -e "${GREEN}✓ Restore completed in ${DURATION}s${NC}"
echo ""

# Verify collections
echo "Verifying restored collections..."
mongosh \
  "mongodb://${MONGO_HOST}:${MONGO_PORT}/${MONGO_DB}" \
  --quiet \
  --eval "const cols = db.getCollectionNames(); print('Collections: ' + cols.join(', ')); print('Total: ' + cols.length);"

echo ""
echo -e "${GREEN}Restore complete. RTO: ${DURATION} seconds.${NC}"
