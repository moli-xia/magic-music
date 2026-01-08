FROM node:18-bookworm-slim

WORKDIR /app

ENV NODE_ENV=production

COPY magic-music/KuGouMusicApi/package.json magic-music/KuGouMusicApi/package-lock.json ./magic-music/KuGouMusicApi/
RUN cd ./magic-music/KuGouMusicApi && npm ci --omit=dev --no-audit --no-fund

COPY magic-music/backend/NeteaseCloudMusicApi/package.json magic-music/backend/NeteaseCloudMusicApi/package-lock.json ./magic-music/backend/NeteaseCloudMusicApi/
RUN cd ./magic-music/backend/NeteaseCloudMusicApi && npm ci --omit=dev --no-audit --no-fund

COPY . .

ENV PORT=8099
ENV NETEASE_HOST=127.0.0.1
ENV NETEASE_PORT=3002
ENV DB_PATH=/data/magic-music-db.json

VOLUME ["/data"]

EXPOSE 8099

CMD ["sh", "-c", "cd /app/magic-music/backend/NeteaseCloudMusicApi && PORT=$NETEASE_PORT node app.js & node /app/server.js"]

