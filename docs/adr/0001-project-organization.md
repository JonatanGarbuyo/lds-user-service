# 0001 — Organización por features con puertos y adaptadores internos

- **Estado:** Aceptado
- **Fecha:** 2026-10-19
- **Contexto:** [especificación #9](https://github.com/JonatanGarbuyo/lds-user-service/issues/9), [addendum arquitectónico](https://github.com/JonatanGarbuyo/lds-user-service/issues/9#issuecomment-6278138059), [T00 #28](https://github.com/JonatanGarbuyo/lds-user-service/issues/28)

## Contexto

El servicio necesita incorporar Identity, Sessions, Administration y Reader State sin acoplar casos de uso a HTTP, SQL ni proveedores concretos. La alternativa aprobada es una organización principal por feature, con puertos definidos por la feature consumidora y adaptadores de infraestructura intercambiables. T00 sólo debe preparar el entorno y la estructura; no debe anticipar paquetes de negocio ni capas vacías.

## Decisión

1. **La estructura principal del producto se organiza por feature:** `identity`, `sessions`, `administration` y `readerstate`, a medida que cada ticket las incorpore. Cada feature es propietaria de su dominio, casos de uso y puertos.
2. **Los puertos/interfaces los define la feature que los consume**, no el adaptador. Por ejemplo, cuando T01 incorpore registro, `identity` declarará `UserRepository` y el adaptador PostgreSQL lo implementará.
3. **La infraestructura transversal vive en `internal/platform/`.** La configuración, el servidor HTTP y los adaptadores de infraestructura compartidos no pertenecen a una feature concreta.
4. **Los adaptadores concretos implementan puertos y se mantienen sustituibles.** El nombre del adaptador comunica la implementación real: `platform/postgres` se mantiene porque identifica PostgreSQL, aunque el contrato que implemente se defina en otra feature.
5. **La composición es explícita en el entrypoint** (`cmd/server`). Sólo se introducirá `internal/app` si la composición de dependencias deja de ser legible en el entrypoint.
6. **No se crean paquetes vacíos ni capas ficticias.** `identity`, `sessions`, `administration` y `readerstate` aparecerán con el ticket que aporte su primer comportamiento real.
7. **No se usan paquetes genéricos `common` o `utils`** como depósito de código sin propietario. El código compartido debe tener una responsabilidad y un lugar explícitos.

## Consecuencias

- T00 deja `internal/platform/config`, `internal/platform/httpserver` e `internal/platform/postgres`, sin features de negocio.
- Los transportes y adaptadores dependen de puertos; el dominio y los casos de uso no dependen de HTTP ni de PostgreSQL.
- Incorporar un nuevo motor SQL o proveedor implica un adaptador y sus migraciones, sin reescribir el dominio.
- La estructura puede crecer por ticket sin obligar a rellenar paquetes prematuramente.
- Cualquier desviación de esta organización debe justificarse en una nueva ADR que reemplace o complemente esta decisión.
