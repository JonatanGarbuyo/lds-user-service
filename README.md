# LDS User Service

Servicio independiente de gestión de usuarios para aplicaciones consumidoras. Su núcleo cubre registro, autenticación y recuperación de acceso; puede ampliarse mediante módulos, como suscripciones y comentarios.

## Estado actual: T00 — entorno de desarrollo

Esta rama implementa **sólo el entorno reproducible** descrito en el ticket [#28](https://github.com/JonatanGarbuyo/lds-user-service/issues/28). Todavía **no** existen funcionalidades de negocio: no hay registro, login, sesiones, usuarios, correo ni administración.

El binario arranca un servidor HTTP mínimo con dos comprobaciones provisionales:

- `GET /healthz` — prueba de vida del proceso.
- `GET /readyz` — prueba de disponibilidad; comprueba PostgreSQL.

Los contratos definitivos de probes se definirán en T17. No deben considerarse un compromiso de compatibilidad.

## Requisitos

- Docker Engine con Docker Compose v2.
- `make`.
- Go **1.26.4** sólo si se ejecutan tests, lint o el servidor fuera de Docker. La versión está fijada en `go.mod` y en el `Dockerfile`.

No se necesita PostgreSQL instalado en el host: Compose levanta una instancia externa al proceso Go, con volumen persistente.

## Arranque rápido

Hay un único flujo de arranque:

```bash
cp .env.example .env
make up
make migrate
curl http://127.0.0.1:8080/healthz
curl http://127.0.0.1:8080/readyz
```

`make up` construye la imagen y arranca PostgreSQL y el servicio en segundo plano. `make migrate` aplica las migraciones **explícitamente**; el servidor nunca las ejecuta al iniciar.

Para desarrollo con logs en primer plano:

```bash
make dev
```

Para detener los contenedores conservando los datos:

```bash
make down
```

> **Advertencia:** `make clean` ejecuta `docker compose down -v` y **elimina el volumen de PostgreSQL y todos los datos de desarrollo**. No hay recuperación automática.

`.env` no se versiona. `.env.example` contiene únicamente credenciales locales de desarrollo.

## Variables de entorno

| Variable | Por defecto | Uso |
|---|---|---|
| `APP_ENV` | `development` | Entorno lógico de la aplicación. |
| `HTTP_ADDR` | `:8080` | Dirección de escucha dentro del contenedor. |
| `DATABASE_URL` | — (obligatoria) | URL `postgres://` o `postgresql://` de PostgreSQL. |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn` o `error`. |
| `SHUTDOWN_TIMEOUT` | `10s` | Tiempo máximo para el apagado ordenado. |
| `DB_CONNECT_TIMEOUT` | `5s` | Tiempo máximo para abrir y comprobar la conexión inicial. |
| `DB_MAX_CONNS` | `10` | Tamaño máximo del pool de conexiones. |
| `HTTP_PORT` | `8080` | Puerto del host publicado por Compose. |
| `POSTGRES_DB` | `lds_user_service` | Base de datos de desarrollo. |
| `POSTGRES_USER` | `lds` | Usuario de PostgreSQL de desarrollo. |
| `POSTGRES_PASSWORD` | `lds_dev_password` | Contraseña local; nunca usar en producción. |
| `POSTGRES_PORT` | `5432` | Puerto de PostgreSQL publicado en `127.0.0.1`. |

Compose aplica valores por defecto aunque `.env` no exista, pero copiar `.env.example` deja la configuración explícita.

## Comandos

| Comando | Descripción |
|---|---|
| `make dev` | Construye y ejecuta el stack en primer plano. |
| `make up` | Construye y ejecuta el stack en segundo plano. |
| `make down` | Detiene los contenedores y conserva el volumen. |
| `make clean` | Detiene los contenedores y **borra el volumen**. |
| `make logs` / `make ps` | Logs del servicio / estado de contenedores. |
| `make run` | Ejecuta el servidor Go en el host (carga `.env` si existe). |
| `make build` | Compila todos los paquetes. |
| `make test` | Tests unitarios. |
| `make test-race` | Tests unitarios con detector de carreras. |
| `make test-integration` | Tests con etiqueta `integration` contra el PostgreSQL de Compose. |
| `make lint` | golangci-lint fijado en `v2.15.0`. |
| `make fmt` | Formatea con gofmt. |
| `make fmt-check` | Falla si hay archivos sin formatear. |
| `make vet` | Ejecuta `go vet`. |
| `make migrate` | Aplica migraciones pendientes. |
| `make migrate-down` | Revierte una migración. |
| `make migrate-version` | Muestra la versión aplicada. |
| `make migrate-force VERSION=<n>` | Fija la versión sin ejecutar SQL; sólo para reparar un estado *dirty*. |
| `make ci` | Ejecuta formato, vet, build, tests y lint localmente. |

## Migraciones

La herramienta es [golang-migrate](https://github.com/golang-migrate/migrate) `v4.20.1`, integrada en `cmd/migrate` y con las migraciones embebidas en el binario. No se requiere instalar un CLI adicional.

Las migraciones viven en `migrations/` y siguen el formato:

```text
<version>_<descripcion>.up.sql
<version>_<descripcion>.down.sql
```

El baseline `000001_baseline` es intencionadamente un no-op: permite comprobar el mecanismo de aplicación, rollback y consulta de versión sin crear tablas de negocio. golang-migrate crea su propia tabla de control `schema_migrations`. Los tickets funcionales añadirán migraciones reales.

```bash
make migrate            # aplica todo lo pendiente
make migrate-version    # consulta la versión y si está dirty
make migrate-down       # revierte un paso
```

Las migraciones no se ejecutan automáticamente al arrancar el servidor ni al hacer `make up`.

## Pruebas y calidad

```bash
make test
make test-race
make test-integration   # espera PostgreSQL healthy y ejecuta tests con -tags=integration
make fmt-check
make lint
```

Los tests unitarios cubren la configuración y el ciclo de arranque/apagado del servidor HTTP, incluidas las respuestas de `/healthz` y `/readyz`. `make test-integration` arranca PostgreSQL con `docker compose up -d --wait postgres` (espera el healthcheck), deriva `TEST_DATABASE_URL` de `.env` —o de los valores por defecto— y ejecuta `go test -tags=integration ./...`. Se puede sobrescribir con `TEST_DATABASE_URL=...` si se usan credenciales o puerto no estándar; en ese caso la URL debe estar codificada para URL.

## CI

`.github/workflows/ci.yml` ejecuta en cada push a `main` y en cada pull request:

1. `go build ./...`, `go vet ./...`, comprobación de `gofmt`, `go test -race ./...` y golangci-lint `v2.15.0`.
2. Aplicación, consulta y rollback de migraciones contra un PostgreSQL 17 real.
3. Smoke test de Docker Compose: arranque, espera de `/readyz`, migraciones, healthcheck del contenedor y limpieza de volúmenes.

Para reproducirlo localmente:

```bash
go build ./...
go vet ./...
gofmt -l $(git ls-files '*.go')
go test -race ./...
make lint
make up
make migrate
curl -fsS http://127.0.0.1:8080/readyz
make clean
```

## Estructura

```text
cmd/server/                    punto de entrada del servicio
cmd/migrate/                   CLI de migraciones
internal/platform/config/      carga y validación de configuración
internal/platform/httpserver/  transporte HTTP mínimo y ciclo de vida
internal/platform/postgres/    adaptador PostgreSQL (pgx)
migrations/                    migraciones versionadas y runner embebido
docs/adr/                      decisiones de arquitectura
```

La infraestructura transversal vive bajo `internal/platform/`. La estructura principal por features y los puertos/adaptadores internos se documentan en [ADR-0001](docs/adr/0001-project-organization.md); las features de negocio se incorporarán con sus tickets, sin crear paquetes vacíos.

## Troubleshooting

- **El puerto 8080 o 5432 está ocupado:** cambiá `HTTP_PORT` o `POSTGRES_PORT` en `.env` y volvé a ejecutar.
- **`/readyz` devuelve 503:** revisá `make logs` y la salud de PostgreSQL con `make ps`; confirmá `DATABASE_URL` y credenciales.
- **La aplicación no arranca por conexión a PostgreSQL:** esperá a que el healthcheck de PostgreSQL esté sano (`make ps`) y revisá los logs de ambos servicios.
- **Migración en estado `dirty`:** inspeccioná `schema_migrations`, corregí el SQL y usá `make migrate-force VERSION=<última versión válida>` con cuidado antes de reintentar.
- **`go: command not found`:** instalá Go 1.26.4. `make up` no requiere Go local, pero `make test`, `make lint` y `make run` sí.
- **Quiero empezar de cero:** `make clean` elimina contenedores y el volumen; después `make up && make migrate`.
