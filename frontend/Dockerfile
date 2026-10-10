FROM node:24.14.1-alpine3.23 AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:1.28.0-alpine3.21
COPY nginx.conf.template /etc/nginx/nginx.conf.template
COPY docker-entrypoint.sh /docker-entrypoint.sh
COPY --from=build /app/dist /usr/share/nginx/html
USER nginx
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s CMD sh -c 'wget -q -O /dev/null "http://127.0.0.1:${PORT:-8080}/health" || exit 1'
ENTRYPOINT ["sh", "/docker-entrypoint.sh"]
