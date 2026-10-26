# traefik с JA4 (поле access-лога TLSClientJA4 и заголовок X-Ja4 для правил
# роутеров) для стенда emperor: официальный образ того же
# тега, у которого заменён только бинарь — собранный из этой ветки (патч JA4
# поверх тега). Живёт здесь, пока PR в upstream (traefik/traefik#12421) не влит.
#
# Собирается из корня репозитория:
#   docker build -f emperor/Dockerfile --build-arg TRAEFIK_VERSION=v3.7.16 --build-arg IMAGE_TAG=v3.7.16-ja4 .
#
# Веб-интерфейс (дашборд) в бинарь не собирается: на стенде он выключен
# (--api.dashboard=false), а сборка webui тянет node.
ARG TRAEFIK_VERSION=v3.7.16
# Версия, которую печатает `traefik version`, — тег образа.
ARG IMAGE_TAG=${TRAEFIK_VERSION}-ja4

# Go 1.26 — как у upstream (.go-version): модуль traefik v3.7 требует go >= 1.26.
FROM golang:1.26-alpine AS build
ARG IMAGE_TAG
WORKDIR /src
COPY go.mod go.sum ./
# go.mod подменяет github.com/traefik/traefik/dynamic/ext локальным подмодулем (v3.7+).
COPY pkg/config/dynamic/ext/go.mod pkg/config/dynamic/ext/go.sum* ./pkg/config/dynamic/ext/
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w \
      -X github.com/traefik/traefik/v3/pkg/version.Version=${IMAGE_TAG} \
      -X github.com/traefik/traefik/v3/pkg/version.Codename=langres" \
    -o /traefik ./cmd/traefik

FROM traefik:${TRAEFIK_VERSION}
COPY --from=build /traefik /usr/local/bin/traefik
