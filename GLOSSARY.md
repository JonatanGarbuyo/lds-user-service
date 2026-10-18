# LDS User Service

Servicio independiente de gestión de usuarios para aplicaciones consumidoras. Su núcleo cubre registro, autenticación y recuperación de acceso; puede ampliarse mediante módulos, como suscripciones y comentarios.

## Language

**User Service**:
Servicio responsable de las identidades de usuario y sus flujos de acceso; ofrece capacidades opcionales sin obligar a las aplicaciones consumidoras a implementarlas.

**User**:
Identidad de una persona que utiliza una aplicación consumidora. Tiene un identificador propio y estable, independiente de su dirección de email.
_Avoid_: Admin, suscriptor (cuando se refiere a identidad).

**Administrator**:
Identidad diferenciada de un User, autorizada a operar y administrar el User Service.
_Avoid_: User con rol de admin.

**Email Verification**:
Comprobación de que una persona controla la dirección de email asociada a su identidad. Es independiente de haber iniciado sesión.

**Pending Email Change**:
Solicitud de sustitución de la dirección de email de un User; la dirección actual se mantiene hasta que se confirme el control de la nueva.

**Suspension**:
Estado impuesto administrativamente que impide la autenticación de un User y termina el acceso de sus sesiones activas.

**Account Deletion**:
Terminación solicitada de una identidad de usuario, que revoca el acceso sin implicar necesariamente la eliminación inmediata de datos sujetos a obligaciones de conservación.

**Reader State**:
Representación temporal del estado de registro y los derechos de acceso de un lector, utilizada para personalizar la experiencia del sitio. No constituye por sí misma una credencial que autorice operaciones protegidas.

**Registered**:
Condición de una identidad User que tiene una cuenta creada. No implica suscripción comercial ni un derecho premium.

**Subscription**:
Relación comercial con un período de facturación y una política de renovación. Puede dar origen a concesiones de acceso, pero no equivale a un permiso efectivo.

**Subscriber**:
User que mantiene una relación comercial de suscripción; no debe usarse como sinónimo de User ni de titular de un Entitlement.

**Entitlement**:
Derecho efectivo de una identidad a una capacidad identificada de forma estable, independientemente del proveedor de pago o del plan comercial.

**Entitlement Grant**:
Concesión individual de una capacidad a un User, con origen, vigencia y trazabilidad propios. Varias concesiones vigentes pueden sustentar el mismo derecho.

**Billing**:
Módulo opcional responsable de modelar la relación comercial y normalizar eventos verificados de distintos proveedores de pago, desacoplado de la autorización efectiva.

**Comments**:
Módulo opcional responsable de publicación, moderación y políticas de conservación del contenido aportado por usuarios.
