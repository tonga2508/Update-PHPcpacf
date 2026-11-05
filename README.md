1. Comprobaciones sin modificar configuraciones ni servicios:
python3 actualizar_php84_phpmyadmin.py --check
2. Compilación e instalación separada, con pruebas antes de activar:
python3 actualizar_php84_phpmyadmin.py --prepare
Prueba extensiones, FPM, Nginx, sesiones, acceso al socket de MariaDB y la pantalla de ingreso de phpMyAdmin.
3. Si todo pasa, mostrará el comando de activación con --apply --prepared. Esa etapa hace respaldos vuelve a comprobar y contempla restauración automática si falla el cambio.
Validé la sintaxis y simulé fallos para probar la restauración. La compilación y las pruebas reales se harán en la máquina destino. El login con un usuario de base requiere la opción adicional --db-test-file, documentada en --help.
Los valores predeterminados corresponden al vhost tasas, dominio tasas2.cpacf.org.ar y raíz /var/www
