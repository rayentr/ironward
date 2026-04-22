FROM node:20-slim

# jq for JSON parsing in entrypoint, nothing else.
RUN apt-get update \
 && apt-get install -y --no-install-recommends jq ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Install ironward globally.
RUN npm install -g ironward@latest

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
