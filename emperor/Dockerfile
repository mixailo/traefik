# traefik с JA4 (поле access-лога TLSClientJA4 и заголовок X-Ja4 для правил
# роутеров) для стенда emperor: официальный образ того же
# тега, у которого заменён только бинарь — собранный из этой ветки (патч JA4
# поверх тега). Живёт здесь, пока PR в upstream (traefik/traefik#12421) не влит.
#
# Собирается из корня репозитория:
#   docker build -f emperor/Dockerfile --build-arg TRAEFIK_VERSION=v3.6.6 --build-arg IMAGE_TAG=v3.6.6-ja4.2 .
#
# Веб-интерфейс (дашборд) в бинарь не собирается: на стенде он выключен
# (--api.dashboard=false), а сборка webui тянет node.
ARG TRAEFIK_VERSION=v3.6.6
# Версия, которую печатает `traefik version`, — тег образа.
ARG IMAGE_TAG=${TRAEFIK_VERSION}-ja4

# Go 1.25: upstream собирал v3.6.6 на 1.24, но её поддержка закончилась, а
# этот бинарь терминирует TLS всей сети. Модуль traefik требует go >= 1.24.
FROM golang:1.25-alpine AS build
ARG IMAGE_TAG
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w \
      -X github.com/traefik/traefik/v3/pkg/version.Version=${IMAGE_TAG} \
      -X github.com/traefik/traefik/v3/pkg/version.Codename=ramequin" \
    -o /traefik ./cmd/traefik

FROM traefik:${TRAEFIK_VERSION}
COPY --from=build /traefik /usr/local/bin/traefik
