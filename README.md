# 魔力音乐（magic-music）

一个自托管的网页音乐播放器，提供多平台搜索/播放能力，并集成简单的管理后台与本地数据存储。

## 功能

- 播放栏持续播放（页面内路由跳转不刷新、不打断播放）
- 多平台音乐能力（当前集成：酷狗；网易云通过本地 API 服务代理）
- 登录/会话、歌单/收藏/最近播放等本地数据
- 管理后台（`/admin.html`）

## 目录结构

```
magic-music/
  index.html                # 前台单页入口
  admin.html                # 管理后台页面
  server.js                 # Node 服务（静态站点 + API + 代理）
  magic-music/              # 第三方/集成的 API 服务代码
    KuGouMusicApi/          # 酷狗 API（server.js 会按需拉起）
    backend/
      NeteaseCloudMusicApi/ # 网易云 API（需单独启动在 3002）
```

## 快速开始

### 推荐：Docker Hub 一键部署

使用 Docker Hub 镜像一键启动（推荐）：

```bash
docker pull superneed/magic-music:latest
docker run -d --name magic-music --restart unless-stopped -p 8099:8099 superneed/magic-music:latest
```

访问：

- Web：`http://localhost:8099`

如需数据持久化（建议）：

```bash
docker rm -f magic-music
docker run -d --name magic-music --restart unless-stopped \
  -p 8099:8099 \
  -e DB_PATH=/data/magic-music-db.json \
  -v magic-music-data:/data \
  superneed/magic-music:latest
```

可选：Docker Compose（从 Docker Hub 拉取镜像）：

```bash
docker compose pull
docker compose up -d --no-build
```

### 本地运行（Node.js）

#### 1) 启动主服务

确保安装 Node.js（建议 18+），然后在项目根目录执行：

```bash
node server.js
```

默认监听：

- Web：`http://localhost:8099`
- 端口可通过环境变量覆盖：`PORT=8099 node server.js`

#### 2) 安装并启用酷狗 API（按需）

主服务会在访问 `/kugou/*` 时尝试连接本地已存在的酷狗 API 端口；如果未发现可用服务，会尝试从 `magic-music/KuGouMusicApi/app.js` 拉起一个子进程。

首次运行前需要安装依赖：

```bash
cd magic-music/KuGouMusicApi
npm install
```

#### 3) 启用网易云 API（可选）

主服务会把 `/netease/*` 代理到 `127.0.0.1:3002`。如需使用网易云相关能力，请单独启动：

```bash
cd magic-music/backend/NeteaseCloudMusicApi
npm install
PORT=3002 node app.js
```

## 接口与页面

- 前台：`/`
- 管理后台：`/admin.html`
- 主服务 API：`/api/*`
- 酷狗代理：`/kugou/*`
- 网易云代理：`/netease/*`

## 数据文件

运行过程中会在项目根目录生成/使用 `magic-music-db.json` 作为本地数据存储（用户、歌单、收藏、后台账号信息等）。

## 从源码构建镜像（可选）

```bash
docker build -t superneed/magic-music:latest .
docker run -d \
  --name magic-music \
  -p 8099:8099 \
  -e DB_PATH=/data/magic-music-db.json \
  -v magic-music-data:/data \
  --restart unless-stopped \
  superneed/magic-music:latest
```

### 环境变量

- `PORT`：主服务端口，默认 `8099`
- `DB_PATH`：数据文件路径，默认 `./magic-music-db.json`
- `NETEASE_HOST`：网易云 API 目标地址，默认 `127.0.0.1`
- `NETEASE_PORT`：网易云 API 目标端口，默认 `3002`

## 推送镜像到 Docker Hub（superneed/magic-music）

```bash
docker build -t superneed/magic-music:latest .
docker login -u superneed
docker push superneed/magic-music:latest
```

## 部署建议

生产环境建议使用进程守护（如 systemd、pm2 等）启动 `node server.js`，并通过反向代理（Nginx/Caddy）提供 HTTPS 访问。
