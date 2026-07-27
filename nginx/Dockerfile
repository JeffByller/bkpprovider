FROM nginx:alpine

# Remove default config
RUN rm /etc/nginx/conf.d/default.conf

# Copy custom config
COPY default.conf /etc/nginx/conf.d/default.conf

# Set Timezone and Create SSL directory & self-signed fallback certificates
ENV TZ=America/Recife
RUN apk add --no-cache openssl tzdata && \
    cp /usr/share/zoneinfo/$TZ /etc/localtime && \
    echo $TZ > /etc/timezone && \
    mkdir -p /etc/nginx/ssl && \
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
    -keyout /etc/nginx/ssl/selfsigned.key \
    -out /etc/nginx/ssl/selfsigned.crt \
    -subj "/CN=bkp.jeffgsan.com.br"


EXPOSE 80 443
