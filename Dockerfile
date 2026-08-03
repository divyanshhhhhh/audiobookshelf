ARG NUSQLITE3_DIR="/usr/local/lib/nusqlite3"
ARG NUSQLITE3_PATH="${NUSQLITE3_DIR}/libnusqlite3.so"

### STAGE 0: Build client ###
FROM node:20-alpine AS build-client

WORKDIR /client
COPY client/package*.json /client/
RUN npm ci && npm cache clean --force
COPY client/ /client/
RUN npm run generate

### STAGE 1: Build server ###
FROM node:20-alpine AS build-server

ARG NUSQLITE3_DIR

ENV NODE_ENV=production

RUN apk add --no-cache --update \
  curl \
  make \
  python3 \
  g++ \
  unzip

WORKDIR /server

# Copy package.json from root
COPY package*.json /server/

# Copy all server code
COPY server/ /server/

# Download nusqlite3 library (x64 only - works on most systems)
RUN curl -L -o /tmp/library.zip "https://github.com/mikiher/nunicode-sqlite/releases/download/v1.2/libnusqlite3-linux-musl-x64.zip" && \
  unzip /tmp/library.zip -d $NUSQLITE3_DIR && \
  rm /tmp/library.zip

RUN npm ci --only=production

### STAGE 2: Create minimal runtime image ###
FROM node:20-alpine

ARG NUSQLITE3_DIR
ARG NUSQLITE3_PATH

RUN apk add --no-cache --update \
  tzdata \
  ffmpeg \
  tini

WORKDIR /app

# Copy compiled frontend and server from build stages
COPY --from=build-client /client/dist /app/client/dist
COPY --from=build-server /server /app
COPY --from=build-server ${NUSQLITE3_PATH} ${NUSQLITE3_PATH}

EXPOSE 80

ENV PORT=80
ENV NODE_ENV=production
ENV CONFIG_PATH="/config"
ENV METADATA_PATH="/metadata"
ENV SOURCE="docker"
ENV NUSQLITE3_DIR=${NUSQLITE3_DIR}
ENV NUSQLITE3_PATH=${NUSQLITE3_PATH}

ENTRYPOINT ["tini", "--"]
CMD ["node", "index.js"]
