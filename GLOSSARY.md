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
