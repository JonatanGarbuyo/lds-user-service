# LDS User Service

Servicio independiente de gestión de usuarios para aplicaciones consumidoras. Su núcleo cubre registro, autenticación y recuperación de acceso; puede ampliarse mediante módulos, como suscripciones y comentarios.

## Estado actual: T00 (entorno) + T01 (registro) + T02 (Email Verification) + T03 (login web)

El entorno reproducible del ticket [#28](https://github.com/JonatanGarbuyo/lds-user-service/issues/28) sigue vigente. El ticket [#10](https://github.com/JonatanGarbuyo/lds-user-service/issues/10) incorpora el registro básico de User mediante `POST /v1/users`, con persistencia PostgreSQL y contrato OpenAPI 3.1. El ticket [#11](https://github.com/JonatanGarbuyo/lds-user-service/issues/11) incorpora **Email Verification**: emisión del código al registrarse, envío por un adaptador de correo de desarrollo, solicitud/reenvío, confirmación y límites de abuso. El ticket [#12](https://github.com/JonatanGarbuyo/lds-user-service/issues/12) incorpora **login web con sesión opaca y Reader State firmado**: `POST /v1/auth/login`, `GET /v1/users/me`, cookies host-only, CORS/CSRF y `GET /v1/jwks`.

Todavía **no** existen logout, sesiones Bearer, recuperación de contraseña, cambio de email ni administración. Registrar un User o confirmar un email no crea cookie, Bearer ni sesión. `emailVerified` refleja el control real del email; `EMAIL_VERIFICATION_REQUIRED` bloquea el login cuando es `true`.

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
- El hashing Argon2id de contraseñas y códigos de verificación comparte un límite de **2 ejecuciones simultáneas por proceso** para acotar el uso de memoria (2 × 64 MiB). Si ambas están ocupadas, el registro, la solicitud y la confirmación fallan rápido con `503 SERVICE_UNAVAILABLE` y `Retry-After: 1`; no se encola trabajo adicional y una confirmación rechazada no consume intentos.
- `id` es un UUID estable generado por PostgreSQL, independiente del email.
- `emailVerified=false` y `status=active` son conceptos independientes.
- La respuesta no incluye `Set-Cookie` ni `Authorization`, y usa `Cache-Control: no-store`.
- Los errores usan el envelope `error.code`, `error.message`, `error.requestId` y `error.fields` opcional. Se incluye `X-Request-Id` en todas las respuestas.
- Los cuerpos se limitan a 1 MiB y deben usar `Content-Type: application/json`; los campos desconocidos se rechazan.

## Email Verification

Al registrarse, el servicio genera un código numérico de **6 dígitos**, lo persiste como hash Argon2id (sujeto al límite compartido de hashing descrito arriba) y lo envía por el puerto `identity.VerificationEmailSender`. El código tiene **10 minutos** de vigencia, es de **un solo uso**, admite **5 intentos** fallidos y no se expone en respuestas HTTP ni en logs. Un código nuevo invalida el anterior. La generación y el hash del código se preparan antes de persistir el User; si el límite de hashing está saturado, el registro responde `503` y no crea la cuenta, de modo que el reintento no encuentra un `409` inesperado.

El contrato completo está en [`api/openapi.yaml`](api/openapi.yaml). Las operaciones son:

```bash
# Solicitar o reenviar el código. Respuesta genérica 202.
curl -i -X POST http://127.0.0.1:8080/v1/auth/email-verification/request \
  -H 'Content-Type: application/json' \
  -d '{"email":"person@example.com"}'

# Confirmar el código. Respuesta 200 con el User y emailVerified=true.
curl -i -X POST http://127.0.0.1:8080/v1/auth/email-verification/confirm \
  -H 'Content-Type: application/json' \
  -d '{"email":"person@example.com","code":"012345"}'
```

Reglas relevantes:

- `POST /v1/auth/email-verification/request` responde `202 Accepted` con `{"status":"accepted"}` para un email sintácticamente válido, exista o no la cuenta. El hashing del código se ejecuta antes de buscar la cuenta, de modo que el costo dominante sea uniforme y no permita enumerar por tiempo. `202` no afirma que el correo se haya entregado. Si el límite de hashing está saturado, responde `503 SERVICE_UNAVAILABLE` con `Retry-After` sin revelar la existencia de la cuenta.
- El reenvío tiene una espera mínima de **60 segundos** desde el último código emitido. Dentro de esa ventana la solicitud se acepta pero no se genera ni envía otro código.
- Un código nuevo invalida el anterior de forma transaccional. Bajo concurrencia, sólo un código puede consumirse y un código anterior no puede confirmar después de que se emitió uno nuevo.
- `POST /v1/auth/email-verification/confirm` responde `400 INVALID_VERIFICATION_CODE` de forma genérica para códigos incorrectos, vencidos, consumidos, invalidados o agotados, sin revelar si la cuenta existe.
- La confirmación actualiza `emailVerified=true` sin modificar `status` y **sin crear cookie, Bearer ni sesión**.
- Los límites por IP son **10 solicitudes/minuto** en `request` y **20 intentos/minuto** en `confirm`, por proceso. Se devuelve `429 RATE_LIMITED` con `Retry-After` cuando corresponde.
- Cuando el límite compartido de Argon2 está saturado, `confirm` responde `503 SERVICE_UNAVAILABLE` con `Retry-After: 1` antes de verificar el código, por lo que no consume intentos.
- Si el adaptador de correo falla, el registro sigue creando la cuenta (`201`) pero registra el fallo y elimina el desafío no entregado; no se afirma que el correo se haya enviado. La solicitud posterior responde `202` genérico y registra el fallo. El usuario puede reintentar el reenvío.

### Adaptador de correo de desarrollo

T02 incluye un adaptador de desarrollo que escribe cada mensaje como una línea JSON en `MAIL_OUTBOX_FILE` (por defecto `/tmp/lds-user-service-mail/outbox.jsonl`), con permisos `0600`, sin usar servicios cloud. El código nunca se escribe en los logs de la aplicación:

```bash
# Con el stack de Compose:
docker compose exec app tail -n 1 /tmp/lds-user-service-mail/outbox.jsonl

# Con make run en el host:
tail -n 1 /tmp/lds-user-service-mail/outbox.jsonl
```

Cada línea contiene `to`, `subject`, `code`, `expiresAt` y `sentAt`. El archivo se fuerza a permisos `0600` también si ya existía con permisos más amplios.

El adaptador es **sólo para desarrollo**: el servicio se niega a arrancar cuando `APP_ENV` no es `development`, en lugar de escribir códigos en disco en otros entornos. Un transporte de producción (por ejemplo SMTP) queda fuera del alcance de este ticket y deberá implementar el mismo puerto.

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

## Login web y sesión opaca

`POST /v1/auth/login` valida la contraseña Argon2id, el estado de la cuenta y la política `EMAIL_VERIFICATION_REQUIRED`. Si todo es correcto, crea una sesión web persistida cuyo secreto opaco se entrega **sólo** en una cookie host-only `Secure`, `HttpOnly` y `SameSite=Lax`; el JSON nunca contiene ese secreto. La sesión tiene 30 días de inactividad y un límite absoluto configurable (90 días por defecto). Cada operación autenticada renueva la actividad sin superar el límite absoluto.

```bash
# Login y almacenamiento de la cookie en un cookie jar local.
curl -i -c cookies.txt -X POST http://127.0.0.1:8080/v1/auth/login \
  -H 'Content-Type: application/json' \
  -H 'Origin: http://localhost:4321' \
  -d '{"email":"person@example.com","password":"correct horse battery"}'

# Perfil autenticado: sólo la cookie válida autoriza la operación.
curl -i -b cookies.txt http://127.0.0.1:8080/v1/users/me

# Claves públicas para verificar readerState.signedSnapshot (no son credenciales).
curl -i http://127.0.0.1:8080/v1/jwks
```

La respuesta `200` incluye `user`, `session` (sin secreto), `readerState.signedSnapshot` y `csrfToken`. El snapshot es un JWT **ES256** firmado con `kid`, pensado exclusivamente para UX: el backend nunca lo acepta como sustituto de la cookie ni usa sus claims para autorizar. Los clientes deben validar firma, algoritmo, `iss`, `aud` y `exp` contra `GET /v1/jwks`.

Reglas relevantes:

- Contraseña incorrecta y email inexistente comparten `401 INVALID_CREDENTIALS`. Una cuenta con email sin verificar responde `403 EMAIL_NOT_VERIFIED` cuando la política está activa; suspendida o en eliminación responde `403 ACCOUNT_SUSPENDED`.
- La sesión se persiste como hash SHA-256 del secreto; el valor en claro nunca se almacena ni se registra en logs.
- `GET /v1/users/me` exige la cookie de sesión. Un `signedSnapshot` o un header `Authorization` no autentican.
- CORS sólo responde a los orígenes explícitos de `CORS_ALLOWED_ORIGINS` con `Access-Control-Allow-Credentials: true` y `Vary: Origin`. Nunca se combina con `*`.
- Las mutaciones con cookie requieren doble envío CSRF (`lds_csrf` + `X-CSRF-Token`). El login valida `Origin`/`Referer`; un origen no permitido responde `403 FORBIDDEN` y no crea sesión.
- `GET /v1/jwks` es público, cacheable (`Cache-Control: public, max-age=300`) y soporta `ETag`/`304`.
- En desarrollo, si no se configura una clave, se genera una clave ES256 efímera al arrancar. En otros entornos la clave es obligatoria y las claves públicas anteriores pueden mantenerse para rotación.

## Variables de entorno

| Variable | Por defecto | Uso |
|---|---|---|
| `APP_ENV` | `development` | Entorno lógico de la aplicación. El adaptador de correo de desarrollo sólo se permite con `development`; otros valores fallan al arrancar hasta implementar un transporte de producción. |
| `HTTP_ADDR` | `:8080` | Dirección de escucha dentro del contenedor. |
| `DATABASE_URL` | — (obligatoria) | URL `postgres://` o `postgresql://` de PostgreSQL. |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn` o `error`. |
| `SHUTDOWN_TIMEOUT` | `10s` | Tiempo máximo para el apagado ordenado. |
| `DB_CONNECT_TIMEOUT` | `5s` | Tiempo máximo para abrir y comprobar la conexión inicial. |
| `DB_MAX_CONNS` | `10` | Tamaño máximo del pool de conexiones. |
| `MAIL_OUTBOX_FILE` | `/tmp/lds-user-service-mail/outbox.jsonl` | Archivo JSONL del adaptador de correo de desarrollo. No usar en producción. |
| `EMAIL_VERIFICATION_REQUIRED` | `true` | Si es `true`, el login exige `emailVerified=true`. |
| `SESSION_COOKIE_NAME` | `lds_session` | Nombre de la cookie de sesión host-only. |
| `SESSION_IDLE_TTL` | `720h` | Inactividad máxima de una sesión web. |
| `SESSION_ABSOLUTE_TTL` | `2160h` | Vida absoluta máxima de una sesión web; debe ser ≥ `SESSION_IDLE_TTL`. |
| `CORS_ALLOWED_ORIGINS` | vacío | Orígenes exactos separados por coma, por ejemplo `https://app.example.com`. Nunca `*` con credenciales. |
| `READER_STATE_ISSUER` | `lds-user-service` | Claim `iss` del snapshot de Reader State. |
| `READER_STATE_AUDIENCE` | `lds-web` | Claim `aud` del snapshot de Reader State. |
| `READER_STATE_TTL` | `30m` | Vigencia informativa del snapshot firmado. |
| `READER_STATE_PRIVATE_KEY` | vacío | Clave privada ECDSA P-256 en PEM (PKCS#8 o SEC1), inline. |
| `READER_STATE_PRIVATE_KEY_FILE` | vacío | Archivo con la clave privada PEM. Obligatorio fuera de `development` si no se usa la variable inline. |
| `READER_STATE_PREVIOUS_PUBLIC_KEYS` | vacío | Claves públicas PEM anteriores para seguir verificando snapshots durante la rotación. |
| `READER_STATE_PREVIOUS_PUBLIC_KEYS_FILE` | vacío | Archivo con una o más claves públicas PEM anteriores. |
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

Los tests unitarios cubren la configuración, el ciclo de arranque/apagado del servidor HTTP, el caso de uso de registro, las validaciones, el handler HTTP, el hasher Argon2id, la emisión/confirmación de Email Verification, el generador de códigos, el adaptador de correo de desarrollo, el rate limiter en memoria, el servicio de sesiones opacas, cookies host-only, CORS, CSRF, firma/verificación ES256, JWKS y rotación de claves. Los tests de integración aplican las migraciones y ejercitan el flujo HTTP completo contra PostgreSQL real: registro, verificación, login, cookie, `/v1/users/me`, persistencia de sesión tras reinicio, revocación/expiración, códigos de error, CORS/CSRF, JWKS, firma del snapshot, normalización, duplicados, concurrencia, saturación del hashing, antienumeración y límites por IP.

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
internal/identity/                   dominio, registro, Email Verification y login
internal/identity/email/             adaptador de correo de desarrollo (outbox JSONL)
internal/identity/password/          adaptador Argon2id
internal/identity/postgres/          adaptadores PostgreSQL de UserRepository y EmailVerificationRepository
internal/identity/httpapi/           transporte HTTP de registro, verificación, login y /users/me
internal/sessions/                   sesiones opacas, cookie host-only y servicio de sesión
internal/sessions/postgres/          adaptador PostgreSQL de SessionRepository
internal/readerstate/                firma ES256, verificación, JWKS y rotación de claves
internal/readerstate/httpapi/        endpoint público GET /v1/jwks
internal/platform/config/            carga y validación de configuración
internal/platform/httpserver/        transporte HTTP, ciclo de vida, CORS y CSRF
internal/platform/postgres/          pool PostgreSQL compartido (pgx)
internal/platform/ratelimit/         rate limiter en memoria por proceso
migrations/                          migraciones versionadas y runner embebido
docs/adr/                            decisiones de arquitectura
```

La infraestructura transversal vive bajo `internal/platform/`. `internal/identity` contiene el dominio y los casos de uso sin importar PostgreSQL; los adaptadores concretos implementan los puertos de cada feature y se componen en `cmd/server`. La estructura por features y los puertos/adaptadores internos se documentan en [ADR-0001](docs/adr/0001-project-organization.md). El Reader State vive en su propia feature y nunca participa de la autorización.

## Troubleshooting

- **El puerto 8080 o 5432 está ocupado:** cambiá `HTTP_PORT` o `POSTGRES_PORT` en `.env` y volvé a ejecutar.
- **`/readyz` devuelve 503:** revisá `make logs` y la salud de PostgreSQL con `make ps`; confirmá `DATABASE_URL` y credenciales.
- **La aplicación no arranca por conexión a PostgreSQL:** esperá a que el healthcheck de PostgreSQL esté sano (`make ps`) y revisá los logs de ambos servicios.
- **Migración en estado `dirty`:** inspeccioná `schema_migrations`, corregí el SQL y usá `make migrate-force VERSION=<última versión válida>` con cuidado antes de reintentar.
- **No encuentro el código de verificación:** en desarrollo se escribe en `MAIL_OUTBOX_FILE`; no aparece en los logs. Usá `docker compose exec app tail -n 1 /tmp/lds-user-service-mail/outbox.jsonl` o revisá el archivo configurado.
- **El correo no llegó:** T02 incluye sólo el adaptador de desarrollo. Revisá que `MAIL_OUTBOX_FILE` sea escribible; si el adaptador falla, el registro sigue creando la cuenta y el fallo queda en los logs sin exponer el código.
- **`go: command not found`:** instalá Go 1.26.4. `make up` no requiere Go local, pero `make test`, `make lint` y `make run` sí.
- **Quiero empezar de cero:** `make clean` elimina contenedores y el volumen; después `make up && make migrate`.
