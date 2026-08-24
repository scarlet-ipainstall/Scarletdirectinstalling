FROM node:22-bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl tar \
    && rm -rf /var/lib/apt/lists/* \
    && curl -fsSL -o /tmp/zsign.tar.gz https://github.com/zhlynn/zsign/releases/download/v1.1.1/zsign-linux-x86_64.tar.gz \
    && tar -xzf /tmp/zsign.tar.gz -C /usr/local/bin \
    && chmod +x /usr/local/bin/zsign \
    && rm -f /tmp/zsign.tar.gz

WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev
COPY server.js ./
COPY public ./public

ENV PORT=10000
EXPOSE 10000
CMD ["npm", "start"]
