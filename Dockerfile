FROM node:24-bookworm-slim
WORKDIR /app
COPY package.json server.mjs drive.mjs office-rules.mjs ./
RUN mkdir /data && chown node:node /data
USER node
ENV HOST=0.0.0.0 PORT=8080 DATA_DIR=/data
EXPOSE 8080
CMD ["node", "server.mjs"]
