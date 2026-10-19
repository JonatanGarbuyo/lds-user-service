# LDS User Service

Servicio independiente de gestión de usuarios para aplicaciones consumidoras. Su núcleo cubre registro, autenticación y recuperación de acceso; puede ampliarse mediante módulos, como suscripciones y comentarios.

## Estado actual: T00 (entorno) + T01 (registro básico de User)

El entorno reproducible del ticket [#28](https://github.com/JonatanGarbuyo/lds-user-service/issues/28) sigue vigente. El ticket [#10](https://github.com/JonatanGarbuyo/lds-user-service/issues/10) incorpora **exclusivamente el registro básico de User** mediante `POST /v1/users`, con persistencia PostgreSQL y contrato OpenAPI 3.1.

Todavía **no** existen verificación de email, login, logout, sesiones, recuperación de contraseña ni administración. Registrar un User no crea cookie, Bearer ni sesión. `emailVerified` queda en `false` hasta que T02 implemente la verificación.

Probes provisionales del entorno:

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

## Registro de User

El contrato completo vive en [`api/openapi.yaml`](api/openapi.yaml) (OpenAPI 3.1). La única operación pública implementada en T01 es:

```bash
curl -i -X POST http://127.0.0.1:8080/v1/users \
  -H 'Content-Type: application/json' \
  -d '{"email":"person@example.com","password":"correct horse battery"}'
```

Respuesta `201 Created`:

```json
{
  "id": "0f8fad5b-d9cb-469f-a165-70867728950e",
  "email": "person@example.com",
  "emailVerified": false,
  "status": "active",
  "createdAt": "2026-10-19T12:00:00Z",
  "updatedAt": "2026-10-19T12:00:00Z"
}
```

Reglas relevantes:

- El email se recorta y se normaliza a minúsculas antes de persistirse. La columna tiene una restricción única, por lo que dos registros concurrentes con el mismo email producen un único User y un `409 EMAIL_ALREADY_EXISTS` para el resto.
- La contraseña debe tener entre 12 y 256 caracteres. Se almacena como hash **Argon2id** (64 MiB, 3 iteraciones, paralelismo 2, salt aleatorio de 16 bytes) en formato PHC; nunca se devuelve ni se registra en logs.
- `id` es un UUID estable generado por PostgreSQL, independiente del email.
- `emailVerified=false` y `status=active` son conceptos independientes.
- La respuesta no incluye `Set-Cookie` ni `Authorization`, y usa `Cache-Control: no-store`.
- Los errores usan el envelope `error.code`, `error.message`, `error.requestId` y `error.fields` opcional. Se incluye `X-Request-Id` en todas las respuestas.
- Los cuerpos se limitan a 1 MiB y deben usar `Content-Type: application/json`; los campos desconocidos se rechazan.

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

El baseline `000001_baseline` es intencionadamente un no-op: permite comprobar el mecanismo de aplicación, rollback y consulta de versión. La migración `000002_users` crea la tabla mínima `users` con email normalizado único, hash de contraseña, `email_verified`, `status`, timestamps y sus restricciones. golang-migrate crea su propia tabla de control `schema_migrations`. Los siguientes tickets añadirán sus propias migraciones.

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

Los tests unitarios cubren la configuración, el ciclo de arranque/apagado del servidor HTTP, el caso de uso de registro, las validaciones, el handler HTTP y el hasher Argon2id. Los tests de integración aplican las migraciones y ejercitan el flujo HTTP completo contra PostgreSQL real: persistencia, normalización, duplicados, concurrencia, reinicio con un pool nuevo y ausencia de credenciales.

`make test-integration` arranca PostgreSQL con `docker compose up -d --wait postgres` (espera el healthcheck), deriva `TEST_DATABASE_URL` de `.env` —o de los valores por defecto— y ejecuta `go test -tags=integration ./...`. Se puede sobrescribir con `TEST_DATABASE_URL=...` si se usan credenciales o puerto no estándar; en ese caso la URL debe estar codificada para URL.

## CI

`.github/workflows/ci.yml` ejecuta en cada push a `main` y en cada pull request:

1. `go build ./...`, `go vet ./...`, comprobación de `gofmt`, `go test -race ./...`, golangci-lint `v2.15.0` y validación del contrato con Redocly CLI.
2. Aplicación, consulta, rollback y reaplicación de migraciones contra un PostgreSQL 17 real.
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
api/openapi.yaml                     contrato HTTP OpenAPI 3.1
cmd/server/                          punto de entrada y composición de dependencias
cmd/migrate/                         CLI de migraciones
internal/identity/                   dominio, validaciones y caso de uso de registro
internal/identity/password/          adaptador Argon2id
internal/identity/postgres/          adaptador PostgreSQL de UserRepository
internal/identity/httpapi/           transporte HTTP de POST /v1/users
internal/platform/config/            carga y validación de configuración
internal/platform/httpserver/        transporte HTTP y ciclo de vida
internal/platform/postgres/          pool PostgreSQL compartido (pgx)
migrations/                          migraciones versionadas y runner embebido
docs/adr/                            decisiones de arquitectura
```

La infraestructura transversal vive bajo `internal/platform/`. `internal/identity` contiene el dominio y el caso de uso sin importar HTTP ni PostgreSQL; los adaptadores concretos implementan el puerto `identity.UserRepository` y se componen en `cmd/server`. La estructura por features y los puertos/adaptadores internos se documentan en [ADR-0001](docs/adr/0001-project-organization.md).

## Troubleshooting

- **El puerto 8080 o 5432 está ocupado:** cambiá `HTTP_PORT` o `POSTGRES_PORT` en `.env` y volvé a ejecutar.
- **`/readyz` devuelve 503:** revisá `make logs` y la salud de PostgreSQL con `make ps`; confirmá `DATABASE_URL` y credenciales.
- **La aplicación no arranca por conexión a PostgreSQL:** esperá a que el healthcheck de PostgreSQL esté sano (`make ps`) y revisá los logs de ambos servicios.
- **Migración en estado `dirty`:** inspeccioná `schema_migrations`, corregí el SQL y usá `make migrate-force VERSION=<última versión válida>` con cuidado antes de reintentar.
- **`go: command not found`:** instalá Go 1.26.4. `make up` no requiere Go local, pero `make test`, `make lint` y `make run` sí.
- **Quiero empezar de cero:** `make clean` elimina contenedores y el volumen; después `make up && make migrate`.
