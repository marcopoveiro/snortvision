FROM node:20-bookworm-slim

WORKDIR /app

# SSH client needed for connecting to the Snort machine
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-client \
    iptables \
 && rm -rf /var/lib/apt/lists/*

COPY package.json ./
RUN npm install --omit=dev --silent

# Install optional GeoIP (adds ~100 MB, set GEOIP_ENABLE=true in .env to use)
RUN npm install geoip-lite --silent 2>/dev/null || true

COPY . .

# Create all necessary directories
RUN mkdir -p /app/data /app/keys /app/config /etc/snort/rules /var/log/snort \
    && touch /var/log/snort/alert_json.txt

EXPOSE 4000

CMD ["node", "server.js"]