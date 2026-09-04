# Build Go binary
FROM golang:1.24-alpine AS go-builder

WORKDIR /app

# Install build dependencies for CGO
RUN apk add --no-cache git gcc musl-dev

# Cache modules
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source
COPY . .

# Copy public files (including nostr.json backup)

# Build static binary
RUN CGO_ENABLED=1 go build -ldflags="-s -w" -o /app/swarm

# Runtime - minimal Alpine image
FROM alpine:latest

LABEL "language"="go"

WORKDIR /app

# Install runtime dependencies (CA certs for HTTPS, timezone data, backup tools, ffmpeg for video processing)
RUN apk add --no-cache ca-certificates tzdata tar curl ffmpeg

# Copy binary from builder
COPY --from=go-builder /app/swarm /app/swarm

# Copy public files (including nostr.json)
COPY --from=go-builder /app/public /app/public

# Copy templates for dashboard UI
COPY --from=go-builder /app/templates /app/templates

# Preserve a copy of bundled public assets so they can be restored
# when a Docker volume is mounted over /app/public (Bug 2 fix).
# The volume only persists mutable state (nostr.json); bundled assets
# (dashboard.html, convert.html, NostrLogin.js, images) must be copied
# back on startup.
RUN cp -a /app/public /app/public-original

# Create backup of original nostr.json for volume initialization
RUN if [ -f '/app/public/.well-known/nostr.json' ]; then \
        cp /app/public/.well-known/nostr.json /app/public/.well-known/nostr.json.original; \
    fi

# Create backup script
COPY <<'EOF' /app/backup.sh
#!/bin/sh
# Backup script for Swarm relay data
BACKUP_DIR="/app/backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p "$BACKUP_DIR"

# Backup database if it exists and has content
if [ -d "/app/db" ] && [ "$(ls -A /app/db 2>/dev/null)" ]; then
    echo "Backing up database..."
    tar -czf "$BACKUP_DIR/db_backup_$TIMESTAMP.tar.gz" -C /app db/
fi

# Backup blossom files if they exist and have content
if [ -d "/app/blossom" ] && [ "$(ls -A /app/blossom 2>/dev/null)" ]; then
    echo "Backing up blossom files..."
    tar -czf "$BACKUP_DIR/blossom_backup_$TIMESTAMP.tar.gz" -C /app blossom/
fi

# Keep last 5 backups per prefix. A single sort -r across all filenames
# keeps only the alphabetically-largest prefix (db_* sorts after blossom_*),
# so all media backups would be deleted. Apply retention separately.
# (B5 fix)
find "$BACKUP_DIR" -name "db_backup_*.tar.gz" -type f | sort -r | tail -n +6 | xargs -r rm
find "$BACKUP_DIR" -name "blossom_backup_*.tar.gz" -type f | sort -r | tail -n +6 | xargs -r rm

echo "Backup completed: $TIMESTAMP"
EOF

# Create restore script
COPY <<'EOF' /app/restore.sh
#!/bin/sh
# Restore script for Swarm relay data
BACKUP_DIR="/app/backups"

if [ ! -d "$BACKUP_DIR" ]; then
    echo "No backup directory found"
    exit 1
fi

# Restore latest database backup
LATEST_DB=$(find "$BACKUP_DIR" -name "db_backup_*.tar.gz" -type f | sort -r | head -n 1)
if [ -n "$LATEST_DB" ]; then
    echo "Restoring database from: $LATEST_DB"
    mkdir -p /app/db
    tar -xzf "$LATEST_DB" -C /app/
fi

# Restore latest blossom backup
LATEST_BLOSSOM=$(find "$BACKUP_DIR" -name "blossom_backup_*.tar.gz" -type f | sort -r | head -n 1)
if [ -n "$LATEST_BLOSSOM" ]; then
    echo "Restoring blossom files from: $LATEST_BLOSSOM"
    mkdir -p /app/blossom
    tar -xzf "$LATEST_BLOSSOM" -C /app/
fi

echo "Restore completed"
EOF

# Create startup script
COPY <<'EOF' /app/start.sh
#!/bin/sh
# Startup script with backup/restore logic

# Restore bundled public assets that are hidden by the Docker volume.
# The volume mounts over /app/public, hiding all image-bundled files.
# Two-step copy so that:
#   - .well-known/ (user-managed nostr.json NIP-05 data) is only filled in
#     when missing, never overwritten (cp -rn on the hidden directory).
#   - All non-hidden dashboard assets (dashboard.html, js/, etc.) are
#     overwritten so stale versions from a previous image do not persist
#     across upgrades (cp -rf with a non-dot glob). (B10 fix)
if [ -d '/app/public-original' ]; then
    echo 'Restoring bundled public assets...'
    cp -rn /app/public-original/.well-known /app/public/ 2>/dev/null || true
    cp -rf /app/public-original/* /app/public/ 2>/dev/null || true
    echo 'Bundled public assets restored'
fi

# Initialize NIP-05 volume if empty
if [ ! -f '/app/public/.well-known/nostr.json' ]; then
    echo 'Initializing NIP-05 volume with default nostr.json...'
    mkdir -p /app/public/.well-known
    # Copy from the original file in the image
    if [ -f '/app/public/.well-known/nostr.json.original' ]; then
        cp /app/public/.well-known/nostr.json.original /app/public/.well-known/nostr.json
    else
        # Create default if no original exists
        echo '{"names":{}}' > /app/public/.well-known/nostr.json
    fi
    echo 'NIP-05 volume initialized'
fi

# Restore from backup if data directories are empty
if [ ! -d '/app/db' ] || [ "$(ls -A /app/db 2>/dev/null)" = '' ]; then
    echo 'Database directory empty, attempting restore...'
    /app/restore.sh
fi

if [ ! -d '/app/blossom' ] || [ "$(ls -A /app/blossom 2>/dev/null)" = '' ]; then
    echo 'Blossom directory empty, attempting restore...'
    /app/restore.sh
fi

# Start the relay
exec /app/swarm
EOF

# Make scripts executable
RUN chmod +x /app/backup.sh /app/restore.sh /app/start.sh

# Create data directories
RUN mkdir -p /app/db /app/blossom /app/backups

EXPOSE 3334

# Set default environment variables (can be overridden by Zeabur env vars)
ENV CGO_ENABLED=1
ENV DOCKER_ENV=true
ENV RELAY_PORT=3334
ENV RELAY_NAME="Swarm Relay"
ENV RELAY_PUBKEY="8ad8f1f78c8e11966242e28a7ca15c936b23a999d5fb91bfe4e4472e2d6eaf55"
ENV RELAY_DESCRIPTION="Team Nostr relay"
ENV DB_ENGINE=badger
ENV DB_PATH=/app/db/
ENV NPUB_DOMAIN=
ENV TEAM_DOMAIN=
ENV BLOSSOM_ENABLED="true"

# S3/Tigris Storage (optional - defaults to filesystem) Otherwise, use "s3"
ENV STORAGE_BACKEND=filesystem
ENV S3_ENDPOINT=""
ENV S3_BUCKET=""
ENV S3_REGION=auto
ENV S3_PUBLIC_URL=""
# AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY should be set via secrets, not in Dockerfile

# Use startup script as entrypoint
ENTRYPOINT ["/app/start.sh"]
