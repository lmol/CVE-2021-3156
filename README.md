# Título del Proyecto

Generador de exploit para CVE-2021-3156 sudo

## Instalación

1. Instala dependencias ./install.sh
2. Ejecuta generador de exploit: ./run.sh
3. Si la versión de sudo del sistema es vulnerable se genera un exploit para la versión instalada 
4. El exploit se genera en exploit.c y el binario ./exploit

## Requisitos

1. gdb gcc make python3 python3-distro
2. glibc con tcache
3. En la actualidad sistemas operativos Ubuntu, Debian.
## Testeado

- Ubuntu 20.04.1
- Ubuntu 20.04.2
- Ubuntu 20.10
- Ubuntu 18.04.5
- Debian 10.7.0

## Autor

* **Luis Molina Garzón** - (https://gitlab.iesvirgendelcarmen.com/luis/CVE-2021-3156/)

* **Qualys Research Team.**  (https://blog.qualys.com/vulnerabilities-research/2021/01/26/cve-2021-3156-heap-based-buffer-overflow-in-sudo-baron-samedit)


## Vulnerabilidad

- sudo escapa metacaracteres en la función parse_args en main
- Posteriormente, en set_cmnd, se eliminan los caracteres de escape que no van seguidos de espacio
- sudo asume que parse_args es una precondición de set_cmnd.
- El problema es que las condiciones son distintas en cada parseador. El primero se ejecuta si el modo es (MODE_RUN && MODE_SHELL). El segundo se ejecuta si el modo es (MODE_RUN | MODE_EDIT | MODE_CHECK) Y (MODE_SHELL|MODE_LOGIN_SHELL)
- Existe una forma de no ejecutar el primer parser pero si el segundo: sudoedit -s 
- set_cmnd calcula el tamaño de los argumentos y crea un chunk en el heap para concatenarlos. Después copia cada argumento hasta encontrar un null byte y continua por el siguiente. Si el argumento de entrada finaliza con una '\\' set_cmnd se salta el caracter de escape, copia el null byte pero continua copiando el siguiente argumento como si fuera el mismo. Esto produce un desbordamiento de buffer en el heap. 
- Por tanto si el último argumento finaliza con '\\' set_cmnd desborda el buffer con el contenido de la primera variable de entorno. Si esta variable de entorno termina en '\\' continuará copiando la siguiente.

## Generador Exploit

- Se usa el método 2 descrito en (https://packetstormsecurity.com/files/161160/Sudo-Heap-Based-Buffer-Overflow.html)
- sudo usa glibc nsswitch para leer la base de datos group después del desbordamiento.
- nsswitch crea una estructura de datos service_table en el heap con todas las bases de datos y servicios de nsswitch.conf.
- Los servicios de group tienen el tipo struct service_user.
- La estructura tiene un campo name con el nombre del servicio
- nsswitch carga dinámicamente una librería libnss_[nombre_servicio]_.so.2 en función de la configuración de /etc/nsswitch.conf para cada servicio de la base de datos group.
- El puntero library debe debe sobreescribir a NULL para evitar crash. Además esto provoca que se vuelva a cargar la librería en memoria, en esta ocasión una librería local con la shellcode.
- Se usa la técnica heap grooming o feng shui. Se crean variables de entorno "locales" de tamaño variable para generar un layout en el heap que permita acercar el chunk en el que set_cmnd copia los argumentos con el objetivo que es la estructura service_user de group.
- Justo antes de ejecutar malloc de set_cmnd se miran la tcache del heap para ver los primeros chunks que se van a reciclar y sus tamaños.
- Se ordenan los chunks que forman las bases de datos y servicios de nsswitch. Se recorren de forma ordenada. Se almacena la dirección de memoria del chunk objetivo y el anterior. 
- Se busca en tcache bin un chunk dentro de ese rango.
- Una vez conocida la posición del chunk y su tamaño se genera el exploit.
- Se usa un argumento terminado en '\\' y null byte del tamaño preciso para que se recicle dicho chunk.
- Se crean las variables 'locales' de entorno precisas para crear el layout adecuado. 
- Antes de estas variables 'locales' se genera una variable de entorno del tamaño necesario para llegar a la estructura objetivo. 
- Se sobreescribe la estructura objetivo con null bytes usando arrays de cadenas con el caracter de escape '\\' esto hace que se escriba un null byte en set_cmnd
- Se sobrescribe el name de service_user con 'x/x' para que posteriormente se carge la librería
'libnss_x/x.so.2'
- En la librería se crea un constructor que ejecuta una shellcode.
- Como sudo se ejecuta con bit suid la shell pertenece a root.

## Licencia
Este proyecto está bajo la Licencia GNU GPL
