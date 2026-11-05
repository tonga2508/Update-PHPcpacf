#!/usr/bin/env python3
"""Ubuntu 20.04 x86_64: PHP 8.4.27 + phpMyAdmin 5.2.3.

Uso (root):
  python3 actualizar_php84_phpmyadmin.py --check
  python3 actualizar_php84_phpmyadmin.py --prepare
  python3 actualizar_php84_phpmyadmin.py --apply --prepared /opt/php84-upgrade/RUN
  python3 actualizar_php84_phpmyadmin.py --rollback /root/php84-backup-RUN

--check es el modo predeterminado: no escribe archivos ni cambia servicios.
--prepare descarga, compila e instala en una carpeta separada; levanta FPM y
Nginx temporales para pruebas locales, sin cambiar servicios de produccion.
--apply vuelve a comprobar y probar antes de activar. Si falla la activacion
o las pruebas posteriores, intenta restaurar automaticamente el estado previo.

Dependencias: build-essential autoconf bison re2c pkg-config curl xz-utils
libxml2-dev libsqlite3-dev libssl-dev libcurl4-openssl-dev libjpeg-dev
libpng-dev libfreetype6-dev libonig-dev libreadline-dev libxslt1-dev
libzip-dev libbz2-dev zlib1g-dev. No ejecuta apt ni actualiza Ubuntu/MariaDB.
Si /opt/libzip existe, utiliza su pkgconfig y rpath.

Conserva parametros habituales del php.ini previo (NO copia extensiones 7.4),
el socket SQL real y /etc/phpmyadmin. No carga OPcache por defecto, igual que
la maquina de referencia. No detiene ni deshabilita PHP 7.4, pues otros sitios
pueden seguir utilizandolo. Solo cambia el vhost --site y los accesos CLI en
/usr/local/bin/{php,php-config,phpize}; no altera alternativas de /usr/bin.

Pruebas: configuracion Nginx original/candidata; version, extensiones y ldd;
FPM temporal; HTTP a PHP y phpMyAdmin; sesiones; acceso al socket MariaDB;
SELECT 1 con cliente local; y, opcionalmente, SELECT 1 con usuario de aplicacion
desde FPM, mediante --db-test-file /root/db-test.json (chmod 600).
Formato JSON: {"user":"usuario","password":"clave","database":"base"}.
No crea ni modifica tablas. No sustituye pruebas funcionales de la aplicacion
ni una restauracion de backup. La prueba phpMyAdmin verifica la pagina de
entrada, no automatiza un login ni la ejecucion de consultas en su interfaz.

Personalizar: --site /etc/nginx/sites-enabled/tasas --web-root /var/www
--host tasas2.cpacf.org.ar --scheme https --port 443 --jobs 2.
HTTP de produccion usa conexion local con Host/SNI del vhost. Para esa prueba
local se omite verificar TLS; las descargas HTTPS SI verifican certificados.
Si el vhost exige autenticacion HTTP o bloquea loopback, se detiene/retrocede.
--allowlists no existe: no cambia ACL ni autenticacion para pasar las pruebas.

Los backups contienen configuracion sensible: directorio root 0700.
Mantener las carpetas de preparacion mientras se use esa instalacion.
No ejecutar dos upgrades simultaneos ni modificar Nginx durante el proceso.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import pwd
import grp
import re
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tarfile
import time
import urllib.request

PHP_VERSION = '8.4.27'
PMA_VERSION = '5.2.3'
PREFIX = Path('/opt/php84')
UNIT = Path('/etc/systemd/system/php84-fpm.service')
SOCK = '/run/php/php8.4-fpm.sock'
REQUIRED = '''bcmath bz2 Core ctype curl date dom exif fileinfo filter ftp gd
gettext hash iconv json libxml mbstring mysqli mysqlnd openssl pcntl pcre PDO
pdo_mysql pdo_sqlite Phar posix random readline Reflection session SimpleXML
sockets SPL sqlite3 standard tokenizer xml xmlreader xmlwriter xsl zip zlib'''.split()
FLAGS = '''--prefix=/opt/php84 --with-config-file-path=/opt/php84/etc
--with-config-file-scan-dir=/opt/php84/etc/conf.d --enable-fpm
--with-fpm-user=www-data --with-fpm-group=www-data --enable-bcmath --with-bz2
--with-curl --enable-exif --enable-ftp --enable-gd --with-jpeg --with-freetype
--with-gettext --enable-mbstring --with-mysqli=mysqlnd --with-pdo-mysql=mysqlnd
--with-openssl --enable-pcntl --with-readline --enable-sockets --with-xsl
--with-zip --enable-opcache --with-zlib'''.split()
INI_KEYS = '''memory_limit max_execution_time max_input_time max_input_vars
post_max_size upload_max_filesize max_file_uploads date.timezone
session.save_path session.gc_maxlifetime session.cookie_secure
session.cookie_httponly session.cookie_samesite default_socket_timeout'''.split()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def run(argv, env=None):
    p = subprocess.run([str(x) for x in argv], stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, text=True, env=env)
    if p.returncode:
        raise RuntimeError('{}: {}'.format(argv[0], (p.stderr or p.stdout)[-3000:]))
    return p.stdout


def active(service):
    return subprocess.run(['systemctl', 'is-active', '--quiet', service]).returncode == 0


def enabled(service):
    return subprocess.run(['systemctl', 'is-enabled', '--quiet', service],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write(path, text, mode=0o644):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    os.chmod(str(path), mode)


def atomic_link(path, target):
    path = Path(path)
    tmp = path.with_name(path.name + '.upgrade-' + secrets.token_hex(4))
    os.symlink(str(target), str(tmp))
    os.replace(str(tmp), str(path))


def nginx_candidate(text):
    # Solo directivas activas, no comentarios. No sustituye otros sockets.
    pat = r'(?m)^(\s*fastcgi_pass\s+)unix:/run/php/php(?:7\.4|8\.4)-fpm\.sock(\s*;)'
    result, count = re.subn(pat, lambda m: m[1] + 'unix:' + SOCK + m[2], text)
    require(count > 0, 'El vhost no tiene un fastcgi_pass 7.4/8.4 reconocido.')
    return result


def local_url(args):
    return '{}://{}:{}'.format(args.scheme, args.host, args.port)


def preflight(args):
    require(os.geteuid() == 0, 'Ejecutar como root.')
    osinfo = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    require(osinfo.get('ID', '').strip('"') == 'ubuntu' and
            osinfo.get('VERSION_ID', '').strip('"') == '20.04', 'Solo Ubuntu 20.04; revisar para otra distribucion.')
    require(platform.machine() == 'x86_64', 'Solo x86_64, como el servidor de referencia.')
    for cmd in ['nginx', 'systemctl', 'mysql', 'curl', 'make', 'cc', 'pkg-config', 'tar', 'ldd']:
        require(shutil.which(cmd), 'Falta {}. Instalar las dependencias indicadas en --help.'.format(cmd))
    require(active('nginx'), 'Nginx no esta activo; resolver antes del cambio.')
    require(not Path('/etc/systemd/system/php84-fpm.service').is_symlink(), 'Unidad php84-fpm es enlace o esta masked; revisar manualmente.')
    live_unit_result = subprocess.run(['systemctl', 'show', 'php84-fpm', '--property=FragmentPath', '--value'],
                                      text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    live_unit = live_unit_result.stdout.strip()
    require(not live_unit or live_unit == str(UNIT), 'Hay otra unidad php84-fpm fuera de /etc/systemd/system; revisar antes.')
    run(['nginx', '-t'])
    site = Path(args.site).resolve(strict=True)
    require(str(site).startswith('/etc/nginx/'), 'El vhost debe estar bajo /etc/nginx.')
    require(not Path(args.web_root).is_symlink(), '--web-root debe ser un directorio real.')
    require(Path(args.web_root).is_dir(), 'No existe web-root.')
    pma_link = Path(args.web_root) / 'phpmyadmin'
    require(pma_link.is_symlink() and pma_link.exists(), 'Se espera phpmyadmin como enlace existente y valido.')
    require(Path('/etc/phpmyadmin/config.inc.php').is_file(), 'Falta la configuracion /etc/phpmyadmin/config.inc.php.')
    nginx_candidate(site.read_text())
    live = run(['nginx', '-T'])
    require('# configuration file ' + args.site + ':' in live or
            '# configuration file ' + str(site) + ':' in live, 'El vhost no esta en la configuracion activa de Nginx.')
    require(re.search(r'\b' + re.escape(args.host) + r'\b', site.read_text()), 'El --host no figura en el vhost.')
    for match in re.finditer(r'(?m)^\s*root\s+([^;]+);', site.read_text()):
        require(Path(match[1].strip()).resolve() == Path(args.web_root).resolve(), 'root del vhost no coincide con --web-root.')
    require(re.search(r'(?m)^\s*root\s+', site.read_text()), 'No se detecto root en el vhost; revisar configuracion.')
    sqlsock = run(['mysql', '--protocol=SOCKET', '--connect-timeout=5', '--batch', '--skip-column-names', '-e', 'SELECT @@socket']).strip()
    require(sqlsock.startswith('/') and '\n' not in sqlsock and Path(sqlsock).is_socket(), 'Socket MariaDB no valido.')
    require(run(['mysql', '--protocol=SOCKET', '--connect-timeout=5', '--batch', '--skip-column-names', '-e', 'SELECT 1']).strip() == '1', 'MariaDB no responde SELECT 1.')
    pkg_env = os.environ.copy()
    pkg_env['PKG_CONFIG_PATH'] = '/opt/libzip/lib/pkgconfig:/usr/lib/x86_64-linux-gnu/pkgconfig:/usr/share/pkgconfig'
    for package in ['libxml-2.0', 'sqlite3', 'openssl', 'libcurl', 'libpng', 'libjpeg', 'freetype2', 'oniguruma', 'libxslt', 'libzip', 'zlib']:
        present = subprocess.run(['pkg-config', '--exists', package], env=pkg_env).returncode == 0
        require(present, 'Falta biblioteca de desarrollo pkg-config: ' + package + '. Consultar dependencias en --help.')
    headers = subprocess.run(['cc', '-fsyntax-only', '-x', 'c', '-'], input='#include <bzlib.h>\n#include <readline/readline.h>\n',
                             text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    require(headers.returncode == 0, 'Faltan headers bzip2/readline: instalar libbz2-dev y libreadline-dev.')
    pwd.getpwnam('www-data')
    grp.getgrnam('www-data')
    for path in [PREFIX, Path('/usr/local/bin/php'), Path('/usr/local/bin/php-config'), Path('/usr/local/bin/phpize')]:
        require(not (path.exists() and path.is_file() and not path.is_symlink()), 'No sobrescribo archivo real: {}'.format(path))
    need = 3 * 1024**3
    require(shutil.disk_usage('/opt').free >= need, 'Se necesitan al menos 3 GiB libres en /opt.')
    require(shutil.disk_usage('/root').free >= 512 * 1024**2, 'Se requieren al menos 512 MiB libres para respaldos en /root.')
    if args.db_test_file:
        f = Path(args.db_test_file)
        require(f.stat().st_uid == 0 and stat.S_IMODE(f.stat().st_mode) & 0o077 == 0,
                '--db-test-file debe pertenecer a root y tener permisos 0600.')
        data = json.loads(f.read_text())
        require(all(isinstance(data.get(k), str) and data[k] for k in ['user', 'password', 'database']), 'JSON SQL incompleto.')
    print('OK: Ubuntu, Nginx, vhost, MariaDB, enlace phpMyAdmin y dependencias pkg-config.')
    print('Socket MariaDB: ' + sqlsock)
    print('PHP 7.4 se conserva. Autenticacion SQL de aplicacion: ' + ('se probara' if args.db_test_file else 'NO solicitada; solo socket y SELECT 1 local root'))
    return site, sqlsock


def download(url, dest):
    run(['curl', '--fail', '--location', '--proto', '=https', '--proto-redir', '=https',
         '--retry', '2', '--connect-timeout', '20', '--max-time', '600', '-o', dest, url])


def extract(archive, destination):
    # Release archives cannot escape their destination, including through links.
    destination = Path(destination).resolve()
    with tarfile.open(str(archive)) as tf:
        for member in tf.getmembers():
            resolved = (destination / member.name).resolve()
            require(str(resolved).startswith(str(destination) + '/'), 'Ruta insegura en tar.')
            require(member.isfile() or member.isdir(), 'Enlace/dispositivo inesperado en tar: ' + member.name)
        tf.extractall(str(destination))


def php_env(release):
    e = os.environ.copy()
    e['PHP_INI_SCAN_DIR'] = str(release / 'etc/conf.d')
    return e


def compile_step(argv, cwd, logfile, env):
    print('Ejecutando {}. Log: {}'.format(argv[0], logfile), flush=True)
    with open(str(logfile), 'w') as log:
        result = subprocess.run(argv, cwd=str(cwd), env=env, stdout=log, stderr=subprocess.STDOUT)
    require(result.returncode == 0, 'Fallo {}. Revisar {}'.format(argv[0], logfile))


def prepare(args, site, sqlsock):
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(3)
    work = Path('/opt/php84-upgrade') / stamp
    work.mkdir(parents=True, mode=0o755)
    release = work / 'php84'
    pma = work / ('phpMyAdmin-' + PMA_VERSION + '-all-languages')
    php_tar = work / ('php-' + PHP_VERSION + '.tar.xz')
    manifest = work / 'php-release.json'
    download('https://www.php.net/releases/index.php?json&version=' + PHP_VERSION, manifest)
    records = json.loads(manifest.read_text())['source']
    sha = next((r['sha256'] for r in records if r['filename'] == php_tar.name), '')
    require(re.fullmatch('[a-fA-F0-9]{64}', sha), 'La API oficial no ofrece SHA256 para esta version.')
    download('https://www.php.net/distributions/' + php_tar.name, php_tar)
    require(digest(php_tar).lower() == sha.lower(), 'SHA256 incorrecto para PHP.')
    pma_tar = work / (pma.name + '.tar.gz')
    base = 'https://files.phpmyadmin.net/phpMyAdmin/' + PMA_VERSION + '/' + pma_tar.name
    download(base, pma_tar)
    download(base + '.sha256', work / 'pma.sha256')
    expected = re.search(r'\b[a-fA-F0-9]{64}\b', (work / 'pma.sha256').read_text())
    require(expected and digest(pma_tar).lower() == expected[0].lower(), 'SHA256 incorrecto para phpMyAdmin.')
    extract(php_tar, work)
    extract(pma_tar, work)
    src = work / ('php-' + PHP_VERSION)
    env = os.environ.copy()
    env['PKG_CONFIG_PATH'] = '/opt/libzip/lib/pkgconfig:/usr/lib/x86_64-linux-gnu/pkgconfig:/usr/share/pkgconfig'
    if Path('/opt/libzip/lib').is_dir():
        env['LDFLAGS'] = env.get('LDFLAGS', '') + ' -Wl,-rpath,/opt/libzip/lib'
    compile_step(['./configure'] + FLAGS, src, work / 'configure.log', env)
    compile_step(['make', '-j', str(args.jobs)], src, work / 'make.log', env)
    dest = work / 'destdir'
    compile_step(['make', 'install', 'INSTALL_ROOT=' + str(dest)], src, work / 'install.log', env)
    shutil.move(str(dest / 'opt/php84'), str(release))
    shutil.copy2(str(src / 'php.ini-production'), str(release / 'etc/php.ini'))
    (release / 'etc/conf.d').mkdir(exist_ok=True)
    # Read FPM values rather than CLI values; never copy old extension directives.
    old_fpm = PREFIX / 'sbin/php-fpm'
    if not old_fpm.exists():
        old_fpm = Path('/usr/sbin/php-fpm7.4')
    if old_fpm.exists():
        oldinfo = run([old_fpm, '-i'])
        overrides = []
        for key in INI_KEYS:
            m = re.search(r'(?m)^' + re.escape(key) + r' => (.*?) => ', oldinfo)
            if m and m[1] not in ('no value', ''):
                require('\n' not in m[1] and '"' not in m[1], 'Valor ini no esperado para ' + key)
                overrides.append(key + ' = "' + m[1] + '"')
        write(release / 'etc/conf.d/80-preserved.ini', '\n'.join(overrides) + '\n')
    write(release / 'etc/conf.d/99-local.ini',
          'mysqli.default_socket = "' + sqlsock + '"\n'
          'pdo_mysql.default_socket = "' + sqlsock + '"\n'
          'include_path = ".:/usr/share/php"\n'
          'display_errors = Off\nlog_errors = On\n')
    pool = '''[www]
user = www-data
group = www-data
listen = /run/php/php8.4-fpm.sock
listen.owner = www-data
listen.group = www-data
listen.mode = 0660
pm = dynamic
pm.max_children = 5
pm.start_servers = 2
pm.min_spare_servers = 1
pm.max_spare_servers = 3
catch_workers_output = yes
'''
    write(release / 'etc/php-fpm.d/www.conf', pool)
    write(release / 'etc/php-fpm.conf', '[global]\npid = /run/php/php84-fpm.pid\nerror_log = /var/log/php84-fpm.log\ninclude=/opt/php84/etc/php-fpm.d/*.conf\n')
    # Config is loaded from the existing distro installation, not copied to webroot.
    tmp = work / 'pma-tmp'
    tmp.mkdir(mode=0o700)
    os.chown(str(tmp), pwd.getpwnam('www-data').pw_uid, grp.getgrnam('www-data').gr_gid)
    write(pma / 'config.inc.php', "<?php\nrequire '/etc/phpmyadmin/config.inc.php';\n$cfg['TempDir'] = " + json.dumps(str(tmp)) + ';\n')
    unit = '''[Unit]
Description=PHP 8.4 FastCGI Process Manager
After=network.target
[Service]
Type=simple
ExecStartPre=/usr/bin/install -d -m 0755 /run/php
ExecStart=/opt/php84/sbin/php-fpm --nodaemonize --fpm-config /opt/php84/etc/php-fpm.conf
ExecReload=/bin/kill -USR2 $MAINPID
Restart=on-failure
[Install]
WantedBy=multi-user.target
'''
    write(work / 'php84-fpm.service', unit)
    write(work / 'nginx.site', nginx_candidate(site.read_text()))
    plan = dict(work=str(work), release=str(release), pma=str(pma), site=str(site),
                site_sha=digest(site), sqlsock=sqlsock, php_version=PHP_VERSION,
                host=args.host, scheme=args.scheme, port=args.port, web_root=args.web_root,
                pma_link_target=os.readlink(str(Path(args.web_root) / 'phpmyadmin')))
    write(work / 'plan.json', json.dumps(plan, indent=2), 0o600)
    return plan


def candidate_nginx_test(plan):
    work = Path(plan['work'])
    dest = work / 'nginx-candidate'
    if dest.exists():
        shutil.rmtree(str(dest))
    shutil.copytree('/etc/nginx', str(dest), symlinks=False)
    # Rewrite all duplicate copies of the selected site's resolved path/content.
    real_site = Path(plan['site'])
    old = real_site.read_text()
    for path in dest.rglob('*'):
        if path.is_file():
            try:
                text = path.read_text()
            except UnicodeError:
                continue
            if text == old:
                text = (work / 'nginx.site').read_text()
            text = re.sub(r'(?m)^(\s*include\s+)([\'"]?)/etc/nginx/',
                          lambda m: m[1] + m[2] + str(dest) + '/', text)
            path.write_text(text)
    run(['nginx', '-t', '-c', dest / 'nginx.conf'])


def make_probe(work, args, sqlsock):
    token = secrets.token_hex(24)
    secret = work / 'sql-test.json'
    if args.db_test_file:
        write(secret, Path(args.db_test_file).read_text(), 0o640)
        os.chown(str(secret), 0, grp.getgrnam('www-data').gr_gid)
    elif secret.exists():
        secret.unlink()
    code = '''<?php
if (!hash_equals(TOKEN, $_SERVER['HTTP_X_UPGRADE_TOKEN'] ?? '')) { http_response_code(404); exit; }
ini_set('display_errors', '0');
try {
  if (PHP_VERSION !== EXPECTED) throw new Exception('Version PHP inesperada');
  foreach (REQUIRED as $ext) if (!extension_loaded($ext)) throw new Exception('Falta extension '.$ext);
  $s = @stream_socket_client('unix://'.SQLSOCK, $errno, $errstr, 3);
  if (!$s) throw new Exception('FPM no puede abrir el socket MariaDB');
  fclose($s);
  session_name('upgrade_probe');
  if (!session_start()) throw new Exception('No inicia sesion PHP');
  $_SESSION['probe'] = 'ok'; session_write_close();
  if (!session_start() || ($_SESSION['probe'] ?? '') !== 'ok') throw new Exception('No persiste sesion PHP');
  session_destroy();
  $auth = false;
  if (is_file(SECRET)) {
    $db = json_decode(file_get_contents(SECRET), true, 512, JSON_THROW_ON_ERROR);
    mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
    $conn = new mysqli('localhost', $db['user'], $db['password'], $db['database'], 3306, SQLSOCK);
    if ((int)$conn->query('SELECT 1')->fetch_row()[0] !== 1) throw new Exception('Fallo SELECT 1');
    $conn->close(); $auth = true;
  }
  header('Content-Type: application/json');
  echo json_encode(['ok'=>true, 'version'=>PHP_VERSION, 'sql_auth_tested'=>$auth]);
} catch (Throwable $e) {
  http_response_code(500); header('Content-Type: application/json');
  echo json_encode(['ok'=>false, 'error'=>'Fallo prueba PHP/sesion/SQL; revisar log temporal']);
  error_log('Upgrade probe: '.get_class($e).' codigo '.$e->getCode());
}
'''
    # Substitution uses exact whole tokens, never shell evaluation.
    values = dict(TOKEN=token, EXPECTED=PHP_VERSION, REQUIRED=REQUIRED, SQLSOCK=sqlsock, SECRET=str(secret))
    for key, value in values.items():
        code = re.sub(r'\b' + key + r'\b', lambda m, v=value: json.dumps(v), code)
    return token, code


def request(url, token=None, resolve=None, insecure=False):
    cmd = ['curl', '--silent', '--show-error', '--max-time', '30', '--noproxy', '*']
    if insecure:
        cmd.append('--insecure')
    if token:
        cmd += ['-H', 'X-Upgrade-Token: ' + token]
    if resolve:
        cmd += ['--resolve', resolve]
    output = run(cmd + ['-w', '\n%{http_code}', url])
    body, status = output.rsplit('\n', 1)
    require(status == '200', 'HTTP {} durante prueba local.'.format(status))
    return body


def verify_pma(body):
    low = body.lower()
    require('phpmyadmin' in low and ('name="pma_username"' in low or "name='pma_username'" in low),
            'phpMyAdmin no muestra el formulario de login esperado (auth_type cookie).')
    require(not any(x in low for x in ['fatal error', 'error during session start', 'is deprecated']),
            'phpMyAdmin devuelve errores de PHP/sesion.')


def tests(plan, args):
    work, release, pma = (Path(plan[k]) for k in ['work', 'release', 'pma'])
    require(digest(plan['site']) == plan['site_sha'], 'El vhost cambio desde la preparacion. Preparar de nuevo.')
    require(os.readlink(str(Path(args.web_root) / 'phpmyadmin')) == plan['pma_link_target'], 'El enlace phpMyAdmin cambio. Preparar de nuevo.')
    env = php_env(release)
    php = [release / 'bin/php', '-c', release / 'etc/php.ini']
    result = json.loads(run(php + ['-r', 'echo json_encode([PHP_VERSION,get_loaded_extensions()]);'], env))
    require(result[0] == PHP_VERSION, 'Version candidata incorrecta.')
    missing = set(x.lower() for x in REQUIRED) - set(x.lower() for x in result[1])
    require(not missing, 'Extensiones faltantes: ' + ', '.join(sorted(missing)))
    for exe in [release / 'bin/php', release / 'sbin/php-fpm']:
        require('not found' not in run(['ldd', exe]), 'Faltan bibliotecas dinamicas para ' + str(exe))
    run(php + ['-l', pma / 'config.inc.php'], env)
    candidate_nginx_test(plan)
    test = work / 'tests'
    test.mkdir(exist_ok=True)
    web = test / 'web'
    web.mkdir(exist_ok=True)
    pmalink = web / 'phpmyadmin'
    if not pmalink.is_symlink():
        pmalink.symlink_to(pma)
    token, code = make_probe(work, args, plan['sqlsock'])
    write(web / 'probe.php', code)
    sock = str(test / 'fpm.sock')
    pool = (release / 'etc/php-fpm.d/www.conf').read_text().replace(SOCK, sock)
    write(test / 'fpm.conf', '[global]\nerror_log = ' + str(test / 'fpm.log') + '\n' + pool)
    run([release / 'sbin/php-fpm', '-t', '-c', release / 'etc/php.ini', '-y', test / 'fpm.conf'], env)
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        port = s.getsockname()[1]
    config = '''user www-data;
worker_processes 1;
pid PID;
error_log ERR;
events { worker_connections 64; }
http {
 access_log off;
 fastcgi_temp_path TMP;
 server {
  listen 127.0.0.1:PORT;
  root ROOT;
  location / { index index.php; }
  location ~ \\.php$ {
   try_files $uri =404;
   include /etc/nginx/fastcgi_params;
   fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
   fastcgi_param HTTPS on;
   fastcgi_pass unix:SOCKET;
  }
 }
}
'''
    values = dict(PID=str(test / 'nginx.pid'), ERR=str(test / 'nginx.log'),
                  TMP=str(test / 'fastcgi'), PORT=str(port), ROOT=str(web), SOCKET=sock)
    for k, v in values.items():
        config = re.sub(r'\b' + k + r'\b', lambda m, value=v: value, config)
    write(test / 'nginx.conf', config)
    run(['nginx', '-t', '-c', test / 'nginx.conf'])
    processes = []
    log = open(str(test / 'processes.log'), 'a')
    try:
        processes.append(subprocess.Popen([str(release / 'sbin/php-fpm'), '--nodaemonize',
                          '-c', str(release / 'etc/php.ini'), '-y', str(test / 'fpm.conf')],
                          env=env, stdout=log, stderr=log))
        for _ in range(100):
            if Path(sock).is_socket():
                break
            require(processes[0].poll() is None, 'FPM temporal termino; revisar tests/processes.log.')
            time.sleep(0.1)
        require(Path(sock).is_socket(), 'FPM temporal no creo su socket.')
        processes.append(subprocess.Popen(['nginx', '-c', str(test / 'nginx.conf'), '-g', 'daemon off;'], stdout=log, stderr=log))
        for _ in range(100):
            require(processes[-1].poll() is None, 'Nginx temporal termino; revisar tests/processes.log.')
            with socket.socket() as s:
                if s.connect_ex(('127.0.0.1', port)) == 0:
                    break
            time.sleep(0.1)
        base = 'http://127.0.0.1:' + str(port)
        body = json.loads(request(base + '/probe.php', token))
        require(body.get('ok'), 'Fallo prueba FPM.')
        verify_pma(request(base + '/phpmyadmin/index.php'))
        print('OK: PHP CLI, extensiones, FPM, HTTP, sesiones, socket SQL y login phpMyAdmin.')
        print('Autenticacion SQL desde FPM: ' + ('OK' if body['sql_auth_tested'] else 'NO probada; pasar --db-test-file para probarla.'))
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.send_signal(signal.SIGQUIT)
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        log.close()
        (web / 'probe.php').unlink(missing_ok=True)
        if (work / 'sql-test.json').exists():
            (work / 'sql-test.json').unlink()


def snapshot(path, backup, label):
    path = Path(path)
    if path.is_symlink():
        return dict(kind='link', target=os.readlink(str(path)), path=str(path))
    if path.is_file():
        saved = backup / label
        shutil.copy2(str(path), str(saved))
        return dict(kind='file', backup=str(saved), path=str(path))
    require(not path.exists(), 'Tipo no admitido para snapshot: ' + str(path))
    return dict(kind='absent', path=str(path))


def restore(item):
    path = Path(item['path'])
    if item['kind'] == 'link':
        atomic_link(path, item['target'])
    elif item['kind'] == 'file':
        tmp = path.with_name(path.name + '.restore-' + secrets.token_hex(4))
        shutil.copy2(item['backup'], str(tmp))
        os.replace(str(tmp), str(path))
    elif path.is_symlink() or path.is_file():
        path.unlink()


def rollback(backup):
    backup = Path(backup)
    state = json.loads((backup / 'state.json').read_text())
    print('Restaurando estado anterior desde ' + str(backup), flush=True)
    if state.get('prefix_touched'):
        if active('php84-fpm'):
            run(['systemctl', 'stop', 'php84-fpm'])
        previous = backup / 'php84.previous'
        if os.path.lexists(str(previous)):
            if PREFIX.is_symlink():
                PREFIX.unlink()
            require(not PREFIX.exists(), 'No sobrescribo un directorio inesperado en /opt/php84.')
            shutil.move(str(previous), str(PREFIX))
        elif state['prefix_existed']:
            require(os.path.lexists(str(PREFIX)), 'Faltan instalacion anterior y php84.previous.')
        elif PREFIX.is_symlink():
            PREFIX.unlink()
    # Disable a newly created service before removing its unit file.
    if not state['unit_existed'] and UNIT.exists():
        run(['systemctl', 'disable', 'php84-fpm'])
    for item in reversed(state['files']):
        restore(item)
    run(['systemctl', 'daemon-reload'])
    if state['unit_existed']:
        run(['systemctl', 'enable' if state['enabled'] else 'disable', 'php84-fpm'])
    if state['active']:
        run(['systemctl', 'start', 'php84-fpm'])
    run(['nginx', '-t'])
    run(['systemctl', 'reload', 'nginx'])
    write(backup / 'ROLLED_BACK', datetime.datetime.now().isoformat(), 0o600)
    print('Estado anterior restaurado. PHP 7.4 no fue modificado.')


def activate(plan, args):
    work = Path(plan['work'])
    backup = Path('/root/php84-backup-' + work.name)
    backup.mkdir(mode=0o700)
    shutil.copytree('/etc/phpmyadmin', str(backup / 'phpmyadmin-config'), symlinks=True)
    site = Path(plan['site'])
    pmalink = Path(args.web_root) / 'phpmyadmin'
    files = [snapshot(site, backup, 'nginx.site'), snapshot(UNIT, backup, 'php84-fpm.service'),
             snapshot(pmalink, backup, 'phpmyadmin.link')]
    for name in ['php', 'php-config', 'phpize']:
        files.append(snapshot(Path('/usr/local/bin') / name, backup, name + '.previous'))
    state = dict(files=files, active=active('php84-fpm'), enabled=enabled('php84-fpm'),
                 unit_existed=UNIT.exists(), prefix_existed=os.path.lexists(str(PREFIX)), prefix_touched=False)
    statefile = backup / 'state.json'
    write(statefile, json.dumps(state, indent=2), 0o600)
    # Record the intended directory transaction before stopping any live service.
    probe_path = Path(args.web_root) / ('upgrade-' + secrets.token_hex(12) + '.php')
    try:
        state['prefix_touched'] = True
        write(statefile, json.dumps(state, indent=2), 0o600)
        if state['active']:
            run(['systemctl', 'stop', 'php84-fpm'])
        if state['prefix_existed']:
            shutil.move(str(PREFIX), str(backup / 'php84.previous'))
        atomic_link(PREFIX, plan['release'])
        shutil.copy2(str(work / 'php84-fpm.service'), str(UNIT))
        os.chmod(str(UNIT), 0o644)
        run(['systemctl', 'daemon-reload'])
        run(['systemctl', 'enable', 'php84-fpm'])
        run(['systemctl', 'start', 'php84-fpm'])
        require(active('php84-fpm'), 'PHP84-FPM no activo.')
        require(Path(SOCK).is_socket(), 'No existe el socket final de FPM.')
        atomic_link(pmalink, plan['pma'])
        # Keep original ownership/mode on Nginx config, then replace atomically.
        pending = site.with_name(site.name + '.pending-' + secrets.token_hex(4))
        shutil.copy2(str(site), str(pending))
        pending.write_text((work / 'nginx.site').read_text())
        os.replace(str(pending), str(site))
        run(['nginx', '-t'])
        run(['systemctl', 'reload', 'nginx'])
        Path('/usr/local/bin').mkdir(exist_ok=True)
        for name in ['php', 'php-config', 'phpize']:
            atomic_link(Path('/usr/local/bin') / name, PREFIX / 'bin' / name)
        token, code = make_probe(work, args, plan['sqlsock'])
        write(probe_path, code)
        resolve = '{}:{}:127.0.0.1'.format(args.host, args.port)
        body = None
        last_error = None
        for _ in range(10):
            try:
                body = json.loads(request(local_url(args) + '/' + probe_path.name, token, resolve, args.scheme == 'https'))
                require(body.get('ok'), 'Fallo prueba de PHP en vhost real.')
                break
            except (RuntimeError, ValueError) as error:
                last_error = error
                time.sleep(0.5)
        require(body and body.get('ok'), 'Fallo prueba PHP en vhost real: ' + str(last_error))
        verify_pma(request(local_url(args) + '/phpmyadmin/index.php', resolve=resolve, insecure=args.scheme == 'https'))
        run([PREFIX / 'bin/php', '-v'])
        write(backup / 'SUCCESS', json.dumps(plan, indent=2), 0o600)
        print('ACTIVADO: PHP ' + PHP_VERSION + ' y phpMyAdmin ' + PMA_VERSION)
        print('Rollback: python3 {} --rollback {}'.format(Path(__file__).resolve(), backup))
        print('Probar ahora login real y funciones de la aplicacion. SQL autenticado: ' + str(body['sql_auth_tested']))
    except BaseException:
        print('Fallo la activacion. Intentando rollback automatico.', file=sys.stderr)
        try:
            rollback(backup)
        except Exception as error:
            print('ROLLBACK INCOMPLETO: {}. Backup: {}'.format(error, backup), file=sys.stderr)
        raise
    finally:
        if probe_path.exists():
            probe_path.unlink()
        if (work / 'sql-test.json').exists():
            (work / 'sql-test.json').unlink()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--check', action='store_true')
    modes.add_argument('--prepare', action='store_true')
    modes.add_argument('--apply', action='store_true')
    modes.add_argument('--rollback', metavar='BACKUP')
    parser.add_argument('--prepared', metavar='RUN')
    parser.add_argument('--site', default='/etc/nginx/sites-enabled/tasas')
    parser.add_argument('--web-root', default='/var/www')
    parser.add_argument('--host', default='tasas2.cpacf.org.ar')
    parser.add_argument('--scheme', choices=['http', 'https'], default='https')
    parser.add_argument('--port', type=int, default=443)
    parser.add_argument('--jobs', type=int, default=2)
    parser.add_argument('--db-test-file')
    args = parser.parse_args()
    require(1 <= args.jobs <= 64 and 1 <= args.port <= 65535, 'jobs/port fuera de rango.')
    require(re.fullmatch('[A-Za-z0-9.-]+', args.host), '--host no valido.')
    require(re.fullmatch('/[A-Za-z0-9_./-]+', args.web_root), '--web-root no valido.')
    def interrupted(signum, frame):
        raise KeyboardInterrupt('Interrumpido por senal ' + str(signum))
    signal.signal(signal.SIGTERM, interrupted)
    if args.rollback:
        require(os.geteuid() == 0, 'Ejecutar como root.')
        require(not (Path(args.rollback) / 'ROLLED_BACK').exists(), 'Este backup ya se restauro.')
        rollback(args.rollback)
        return
    # Lock lives only for mutating modes; --check does not create even a lockfile.
    lock = None
    if args.apply or args.prepare:
        import fcntl
        lock = open('/run/php84-upgrade.lock', 'w')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    site, sqlsock = preflight(args)
    if not args.apply and not args.prepare:
        print('CHECK finalizado. Sin archivos/configuraciones/servicios modificados.')
        return
    oldmask = os.umask(0o022)
    try:
        if args.prepared:
            work = Path(args.prepared).resolve()
            require(str(work).startswith('/opt/php84-upgrade/'), 'RUN fuera de /opt/php84-upgrade.')
            plan = json.loads((work / 'plan.json').read_text())
            require(plan['work'] == str(work) and plan['php_version'] == PHP_VERSION, 'Plan de otra version o ubicacion.')
            for key in ['host', 'scheme', 'port', 'web_root']:
                require(plan[key] == getattr(args, key), 'Parametro cambio desde preparacion: ' + key)
            require(plan['site'] == str(site) and plan['sqlsock'] == sqlsock, 'Cambio vhost/socket desde preparacion.')
        else:
            plan = prepare(args, site, sqlsock)
        tests(plan, args)
        if args.apply:
            activate(plan, args)
        else:
            print('PREPARADO y probado, sin activar. RUN: ' + plan['work'])
            print('Siguiente: python3 {} --apply --prepared {}'.format(Path(__file__).resolve(), plan['work']))
    finally:
        os.umask(oldmask)
        if lock:
            lock.close()


if __name__ == '__main__':
    try:
        main()
    except (Exception, KeyboardInterrupt) as exc:
        print('DETENIDO: ' + str(exc), file=sys.stderr)
        sys.exit(1)
