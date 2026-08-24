FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates git g++ make pkg-config libssl-dev zlib1g-dev libminizip-dev nodejs npm \
    && rm -rf /var/lib/apt/lists/* \
    && git clone --depth 1 https://github.com/zhlynn/zsign.git /opt/zsign \
    && cd /opt/zsign/build/linux \
    && make clean && make \
    && cp zsign /usr/local/bin/zsign

WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev
COPY server.js ./
COPY public ./public

ENV PORT=10000
EXPOSE 10000
CMD ["node", "server.js"]
