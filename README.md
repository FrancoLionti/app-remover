# app-remover

Un comando para saber **qué tenés instalado, de dónde viene y cómo se va a desinstalar**.
CLI de texto, sin TUI obligatoria y sin dependencias externas de Python.

```sh
desinstalar plan sunshine freetube ghostty
desinstalar remove sunshine freetube ghostty
```

`plan` solo lee el sistema y simula APT. `remove` muestra el plan, pide escribir
`DESINSTALAR`, vuelve a verificarlo y ejecuta los gestores nativos. APT y Flatpak
mantienen sus propias confirmaciones. No hay `--yes` ni eliminación no interactiva.

## Instalación

Requiere Python 3.10+ y los gestores correspondientes. La implementación inicial
está pensada para Debian/Ubuntu con APT, Flatpak y Snap. AppImages usan `gio` para
moverse a Papelera; las extensiones de usuario usan `gnome-extensions`.

Desde un checkout, sin instalar paquetes ni tocar Python del sistema:

```sh
git clone https://github.com/FrancoLionti/app-remover.git
cd app-remover
./bin/desinstalar --help
mkdir -p ~/.local/bin
ln -s "$(pwd)/bin/desinstalar" ~/.local/bin/desinstalar
```

El enlace no reemplaza un comando existente. `~/.local/bin` debe estar en `PATH`.
También podés instalar el proyecto con `pipx install .` o `uv tool install .`.
No ejecutes `sudo desinstalar`: solo APT y Snap usan `sudo` dentro del plan.

## Uso

```sh
# Diagnóstico, sin cambios
desinstalar plan sunshine syncthing --verbose
desinstalar plan freetube --json

# Plan + confirmación + desinstalación + reporte
desinstalar remove sunshine freetube ghostty
desinstalar sunshine                 # atajo para remove

# Exploración opcional: muestra identificadores de todos los paquetes, incluidas bibliotecas
desinstalar list
desinstalar list teams ghostty
desinstalar list --type flatpak --json
desinstalar list --type extension

# Limitar el diagnóstico a un gestor
desinstalar plan --type apt sunshine

# Elegir exactamente qué instalación quitar
desinstalar plan apt:gnome-shell-extension-gsconnect
desinstalar plan extension:gsconnect@andyholmes.github.io
desinstalar plan flatpak:system:io.freetubeapp.FreeTube/x86_64/stable

# Buscar AppImages en otro directorio de usuario
desinstalar list --appimage-dir ~/Descargas
```

Las búsquedas son insensibles a mayúsculas. Una coincidencia ambigua muestra una
selección numérica en terminal. En `--json` o sin terminal exige identificadores
exactos. Si falla un origen, las búsquedas generales quedan bloqueadas para no
ocultar duplicados; podés usar `--type` o una identidad exacta de un origen verificado.
Un nombre desconocido cancela toda la solicitud antes de ejecutar comandos.

## Qué muestra y qué conserva

| Origen | Diagnóstico | Eliminación y datos |
| --- | --- | --- |
| APT / `.deb` | Simulación real, paquetes afectados, dependientes adicionales, unidades de servicio y `Installed-Size` | `apt-get remove`, conserva configuración. No hace `purge` ni `autoremove`. Bloquea paquetes Essential, Protected y prioridad required, incluidos dependientes. |
| Flatpak | App, arquitectura, rama, instalación, commit y tamaño nominal | `flatpak uninstall` con instalación explícita; conserva datos de la app. El gestor muestra extensiones relacionadas al confirmar. No limpia runtimes sin uso automáticamente. |
| Snap | Nombre, versión, revisión, archivos de revisiones y política de instantáneas | `snap remove`, sin `--purge`. Snap elimina datos activos y normalmente guarda una instantánea; si están deshabilitadas lo advierte. No se promete conservar datos cuando la política no puede verificarse. |
| AppImage | Archivo y lanzadores `.desktop` de usuario identificados | Los mueve a Papelera con `gio trash`. No libera espacio hasta vaciarla. Conserva datos. |
| Extensión GNOME de usuario | UUID, nombre, versión y ruta | `gnome-extensions uninstall`. La instalación APT se trata por separado. Los ajustes dconf quedan; puede requerir cerrar sesión. |

Los tamaños **no son una promesa de espacio recuperable** ni se suman en un total:
APT informa tamaños nominales, Flatpak comparte objetos y Snap puede crear una
instantánea. El reporte posterior mide el cambio neto de espacio libre por filesystem,
sin contar dos veces el mismo dispositivo. Incluye actividad concurrente.

AppImages se detectan en `~/Applications`, `~/AppImages`, `~/.local/bin`,
directorios explícitos y rutas literales referenciadas por lanzadores de usuario.
No ejecuta archivos `.desktop`, no sigue enlaces y no busca en todo el disco.
Las instalaciones manuales, Cargo, pipx, npm, Nix, Wine y otros gestores todavía
no están soportados. No borra archivos desconocidos ni directorios de datos inferidos.

## Reportes y límites

Cada eliminación deja un JSON privado (`0600`) en
`${XDG_STATE_HOME:-~/.local/state}/app-remover/reports/`. Incluye:

- Plan aprobado y resultados de cada comando.
- Verificación de todos los objetivos y dependientes adicionales de APT.
- Estados `removed`, `still_installed` o `unknown`; un fallo de inventario nunca cuenta como éxito.
- Rutas de restos detectados por identidad o coincidencia de nombre, sin borrarlas.
- Cambio observado de espacio libre y lista de instantáneas de Snap, si corresponde.
- Sugerencias de limpieza separadas, que no se ejecutan automáticamente.

No lee el contenido de configuraciones ni de documentos. Los reportes contienen rutas
locales y nombres de aplicaciones: quedan fuera del repositorio.
La detección de restos es parcial; algunas apps usan nombres o ubicaciones distintos.
No identifica exhaustivamente archivos sincronizados, servicios configurados a mano,
procesos abiertos ni todos los lanzadores. Desinstalar Syncthing no es una instrucción
para borrar las carpetas que sincronizaba.

APT tiene simulación nativa. Flatpak y Snap **no** ofrecen aquí un equivalente: sus
impactos se explican y los gestores validan la operación. Entre gestores no hay una
transacción atómica ni rollback: ante el primer fallo se detiene y reporta el estado
real. El plan se recalcula después de confirmar, aunque otros procesos pueden cambiar
el sistema durante la ejecución. La terminal de cada gestor queda visible.

Esto es una primera versión, con pruebas de seguridad funcional; no una auditoría
independiente ni una garantía de ausencia de vulnerabilidades.

## Desarrollo

```sh
python3 -m unittest discover -s tests -v
python3 -m compileall -q app_remover
```

Las pruebas de eliminación usan gestores simulados, nunca desinstalan software del
equipo ni requieren privilegios. Las pruebas cubren ambigüedad, metadatos inesperados,
argumentos literales, dependencias protegidas, planes obsoletos, cancelación, fallos
parciales, inventarios incompletos y permisos del reporte.

Referencias: [APT](https://manpages.debian.org/stable/apt/apt-get.8.en.html),
[Flatpak](https://docs.flatpak.org/en/latest/using-flatpak.html),
[conservación de datos Flatpak](https://docs.flathub.org/docs/for-users/uninstallation),
[instantáneas de Snap](https://snapcraft.io/docs/snapshots/).

Licencia MIT.
