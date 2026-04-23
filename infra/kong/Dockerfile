FROM kong:3.4-alpine

COPY kong.yml /usr/local/kong/declarative/kong.yml

EXPOSE 8000 8443

ENV KONG_DATABASE=off
ENV KONG_DECLARATIVE_CONFIG=/usr/local/kong/declarative/kong.yml
ENV KONG_PROXY_LISTEN=0.0.0.0:8000
ENV KONG_ADMIN_LISTEN=0.0.0.0:8001
ENV KONG_LOG_LEVEL=info
ENV KONG_PLUGINS=bundled,cors,rate-limiting,request-transformer,response-transformer

CMD ["kong", "start", "-c", "/usr/local/kong/declarative/kong.yml"]