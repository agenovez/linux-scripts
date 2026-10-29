#!/usr/bin/env python3
"""Recoleccion acotada de indicadores dbusd. Python 3.6+, Linux, ejecutar como root.
Uso: sudo python3 verificar_dbusd.py /ruta/existente/con/espacio
Opcional: --dias-journal 7 (registros systemd; logs de archivo se leen por cola limitada).
No ejecuta muestras ni detiene procesos. No constituye una imagen forense.
"""
import os
import sys
import stat
import json
import time
import hashlib
import tempfile
import tarfile
import socket
import gzip
import re
import ipaddress
import subprocess
import selectors
import argparse
import csv
import glob

VERSION = '2.0'
NET_MAX = 2000
LOG_TOTAL = 64 * 1024 * 1024
LOG_EACH = 8 * 1024 * 1024

def addresses(text):
    """Literales IPv4/IPv6, sin consultas DNS ni atribucion automatica."""
    found = set()
    tokens = re.findall(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])', text)
    tokens += re.findall(r'(?<![\w:])[0-9A-Fa-f]*:[0-9A-Fa-f:.%]+', text)
    for token in tokens:
        try:
            found.add(str(ipaddress.ip_address(token.split('%')[0])))
        except ValueError:
            pass
    return sorted(found)

def domains(text):
    hosts = re.findall(r'(?:https?://|["\x27])([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(?=[:/"\x27])', text)
    return sorted(set(h.lower() for h in hosts))

DIRS = ('/var/lib/php/sessions/.dbusd', '/var/www/html/.cache/.dbusd', '/dev/shm/.dbusd')
MARKERS = (b'__dbs', b'__dbw', b'__dbd', b'dbusd-guard', b'dbus cache')
PHP_HASH = 'c39586b423faefddc5c9e9204fc94adff7e7bb209bdc579f77ebb00cbddff4a1'
PER_FILE = 16 * 1024 * 1024
TOTAL = 64 * 1024 * 1024
MAX_FILES = 512

def related(path):
    path = path[:-10] if path.endswith(' (deleted)') else path
    return any(path == d or path.startswith(d + '/') for d in DIRS)

class Collector:
    def __init__(self, output, days=7):
        self.output = output
        self.days = days
        self.pids = set()
        self.network = []
        self.net_seen = set()
        self.net_full = False
        self.log_bytes = 0
        self.log_sources = []
        self.check_space(192 * 1024 * 1024)
        self.work = tempfile.mkdtemp(prefix='evidencias-dbusd-' + time.strftime('%Y%m%d-%H%M%S-'), dir=output)
        os.mkdir(self.work + '/muestras', 0o700)
        self.used = 0
        self.count = 0
        self.report = {'version_recolector': VERSION, 'host': socket.gethostname(), 'inicio_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                       'hallazgos': [], 'archivos': [], 'errores_y_omisiones': [],
                       'alcance': 'Indicadores conocidos dbusd; conexiones actuales de PID relacionados y extractos seleccionados de logs. IP candidatas, NO atribucion del atacante. Sin busqueda global. Ausencia no descarta compromiso. Lecturas pueden actualizar atime; kernel/herramientas locales no son fuente independiente de confianza.'}

    def net_event(self, category, source, text, excerpt=True, sample=None):
        ips = addresses(text)
        names = domains(text) if category == 'literal_en_muestra' else []
        if not ips and not names:
            return
        key = (category, source, hashlib.sha256(text.encode('utf-8', 'replace')).hexdigest())
        if key in self.net_seen:
            return
        if len(self.network) >= NET_MAX:
            if not self.net_full:
                self.error('red', 'Limite de 2000 eventos; registros adicionales omitidos')
                self.net_full = True
            return
        self.net_seen.add(key)
        if len(ips) > 64 or len(names) > 64:
            self.error(source, 'Mas de 64 IP o dominios por evento; listado truncado')
        self.network.append({'categoria': category, 'fuente': source, 'ips': ips[:64],
                             'dominios': names[:64], 'muestra': sample,
                             'linea': text[:1024] if excerpt else None,
                             'linea_truncada': excerpt and len(text) > 1024,
                             'atribucion': 'No determinada; correlacionar con accesos autorizados, NAT/proxy y cronologia'})

    def command_lines(self, command, consumer, limit=8*1024*1024, seconds=25):
        """Salida acotada y timeout; sin shell ni comandos tomados de las muestras."""
        proc = None
        try:
            self.check_space(32 * 1024 * 1024)
            proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                    env=dict(os.environ, LC_ALL='C', SYSTEMD_PAGER='cat'))
            selector = selectors.DefaultSelector()
            selector.register(proc.stdout, selectors.EVENT_READ)
            deadline = time.monotonic() + seconds
            total, pending = 0, b''
            while True:
                if time.monotonic() >= deadline:
                    raise RuntimeError('Timeout; salida parcial')
                ready = selector.select(0.2)
                if not ready:
                    continue
                block = os.read(proc.stdout.fileno(), 65536)
                if not block:
                    break
                total += len(block)
                if total > limit:
                    raise RuntimeError('Limite de salida; resultado parcial')
                pending += block
                lines = pending.split(b'\n')
                pending = lines.pop()
                for line in lines:
                    consumer(line[:65536].decode('utf-8', 'replace'))
                if len(pending) > 65536:
                    raise RuntimeError('Linea excesiva; salida parcial')
            if pending:
                consumer(pending.decode('utf-8', 'replace'))
            if proc.wait(timeout=2) != 0:
                self.error(command[0], 'Comando fallo; stderr no conservado')
        except Exception as exc:
            self.error(' '.join(command), exc)
        finally:
            if proc is not None:
                if proc.poll() is None:
                    proc.kill()
                proc.wait()
                proc.stdout.close()
            if 'selector' in locals():
                selector.close()

    def connections(self):
        if not self.pids:
            return
        def selected(line):
            if any(pid in self.pids for pid in re.findall(r'pid=(\d+)', line)):
                self.net_event('socket_de_proceso_relacionado', 'ss -H -ntup', line)
        self.command_lines(['ss', '-H', '-n', '-t', '-u', '-p'], selected)

    def log_line(self, source, line):
        low = line.lower()
        if 'sshd' in low and ('accepted password' in low or 'accepted publickey' in low or 'accepted keyboard-interactive' in low):
            self.net_event('ssh_autenticado_no_atribuido', source, line)
        elif 'sshd' in low and any(x in low for x in ('failed password', 'invalid user', 'authentication failure')):
            self.net_event('ssh_fallido_no_prueba_intrusion', source, line)
        elif any(x in low for x in ('.dbusd', 'xmrig', 'moneroocean', '__dbs', 'dbusd-guard')):
            self.net_event('log_con_indicador_dbusd', source, line)
        elif any(x in low for x in ('cmd=', 'shell_exec', 'base64_decode', '%2edbusd', 'wget%20', 'curl%20', '/bin/sh')):
            self.net_event('peticion_o_evento_sospechoso_no_confirmado', source, line)

    def logs(self):
        # Solo candidatos y lineas relevantes; no se copian logs completos.
        paths = set()
        for pattern in ('/var/log/auth.log*', '/var/log/secure*', '/var/log/apache2/*access*.log*',
                        '/var/log/apache2/*error*.log*', '/var/log/nginx/*access*.log*', '/var/log/nginx/*error*.log*'):
            paths.update(glob.glob(pattern))
        def order(path):
            try: return os.lstat(path).st_mtime
            except OSError: return 0
        for path in sorted(paths, key=order, reverse=True)[:64]:
            if self.log_bytes >= LOG_TOTAL:
                self.error('logs', 'Limite de 64 MiB examinados; logs restantes omitidos'); break
            budget = min(LOG_EACH, LOG_TOTAL - self.log_bytes)
            try:
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(fd, 'rb') as f:
                    st = os.fstat(f.fileno())
                    if not stat.S_ISREG(st.st_mode):
                        self.error(path, 'No regular; omitido'); continue
                    if path.endswith('.gz'):
                        # Se omiten comprimidos: descompresion ilimitada podria consumir CPU.
                        self.error(path, 'Log comprimido no examinado; preservar por separado si se necesita historia'); continue
                    start = max(0, st.st_size - budget)
                    f.seek(start)
                    data = f.read(budget)
                self.log_bytes += len(data)
                self.log_sources.append({'ruta': path, 'offset_inicio': start, 'bytes_leidos': len(data),
                                         'sha256_fragmento_leido': hashlib.sha256(data).hexdigest(),
                                         'mtime_ns': st.st_mtime_ns, 'nota': 'Solo se conservan lineas seleccionadas; sin filtro temporal de archivos'})
                if start:
                    self.error(path, 'Solo ultimos 8 MiB o presupuesto restante; comienzo omitido')
                    data = data.split(b'\n', 1)[-1]
                for line in data.splitlines():
                    self.log_line(path, line[:65536].decode('utf-8', 'replace'))
            except Exception as exc:
                self.error(path, exc)
        if len(paths) > 64:
            self.error('logs', 'Solo los 64 archivos mas recientes')
        source = 'journalctl: ultimos {} dias, maximo 20000 entradas'.format(self.days)
        self.command_lines(['journalctl', '--since', '{} days ago'.format(self.days), '-n', '20000',
                            '--no-pager', '-o', 'short-iso'], lambda line: self.log_line(source, line))
        self.report['alcance_logs'] = {'archivos': self.log_sources, 'journal': source,
            'advertencia': 'Ventana y volumen limitados; logs rotados comprimidos omitidos. SSH aceptado puede ser legitimo; fallido no demuestra entrada. IP de proxy/X-Forwarded-For puede no representar al origen real.'}

    def check_space(self, needed):
        v = os.statvfs(self.output)
        if v.f_bavail * v.f_frsize < needed or (v.f_files and v.f_favail < 1500):
            raise RuntimeError('Espacio/inodos insuficientes. Use otro volumen; no se borran evidencias.')

    def error(self, path, error):
        if len(self.report['errores_y_omisiones']) < 2000:
            self.report['errores_y_omisiones'].append({'ruta': path, 'detalle': str(error)})

    def finding(self, kind, detail):
        self.report['hallazgos'].append({'tipo': kind, 'detalle': detail})

    def collect(self, path, reason, predicate=None, proc=False):
        """Copia solo archivos regulares, lectura limitada; no sigue symlinks salvo /proc validado."""
        fd = None
        try:
            if self.count >= MAX_FILES:
                raise RuntimeError('Limite de 512 archivos alcanzado')
            flags = os.O_RDONLY | os.O_NONBLOCK
            if not proc:
                flags |= os.O_NOFOLLOW
            fd = os.open(path, flags)
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode):
                raise RuntimeError('No es archivo regular; omitido')
            if before.st_size > PER_FILE:
                raise RuntimeError('Supera limite de 16 MiB por archivo; no copiado')
            with os.fdopen(fd, 'rb') as source:
                fd = None
                data = source.read(PER_FILE + 1)
                after = os.fstat(source.fileno())
            if len(data) > PER_FILE:
                raise RuntimeError('Archivo crecio sobre el limite; no copiado')
            if predicate is not None and not predicate(data):
                return False
            self.finding(reason, path)
            if self.used + len(data) > TOTAL:
                raise RuntimeError('Limite total de 64 MiB; evidencia omitida')
            self.check_space(2 * (TOTAL - self.used) + 32 * 1024 * 1024)
            self.count += 1
            name = 'muestras/{:04d}.bin'.format(self.count)
            with open(os.path.join(self.work, name), 'xb') as dest:
                dest.write(data)
            self.used += len(data)
            self.report['archivos'].append({'origen': path, 'copia': name, 'motivo': reason,
                'bytes_copiados': len(data), 'sha256_copia': hashlib.sha256(data).hexdigest(),
                'uid': before.st_uid, 'gid': before.st_gid, 'modo': oct(before.st_mode),
                'inode': before.st_ino, 'dispositivo': before.st_dev, 'enlaces': before.st_nlink,
                'tamano_origen': before.st_size, 'mtime_ns': before.st_mtime_ns,
                'ctime_ns': before.st_ctime_ns, 'atime_ns_antes': before.st_atime_ns,
                'cambio_durante_lectura': (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)})
            if not path.endswith('/status'):
                for number, line in enumerate(data.splitlines(), 1):
                    self.net_event('literal_en_muestra', path + ':linea=' + str(number),
                                   line[:65536].decode('utf-8', 'replace'), excerpt=False, sample=name)
            return True
        except FileNotFoundError:
            self.error(path, 'No existe o desaparecio durante la lectura')
        except Exception as exc:
            self.error(path, exc)
        finally:
            if fd is not None:
                os.close(fd)
        return False

    def tree(self, root, depth=0):
        if depth > 2:
            self.error(root, 'Subdirectorio fuera del limite de profundidad 2')
            return
        try:
            if not stat.S_ISDIR(os.lstat(root).st_mode):
                self.error(root, 'Directorio es enlace u otro tipo; omitido')
                return
            with os.scandir(root) as entries:
                for n, entry in enumerate(entries):
                    if n >= MAX_FILES:
                        self.error(root, 'Limite de entradas por directorio'); break
                    if entry.is_dir(follow_symlinks=False):
                        self.tree(entry.path, depth + 1)
                    else:
                        self.collect(entry.path, 'Archivo en directorio indicador')
        except FileNotFoundError:
            pass
        except Exception as exc:
            self.error(root, exc)

    def processes(self):
        for pid in os.listdir('/proc'):
            if not pid.isdigit() or int(pid) == os.getpid():
                continue
            base = '/proc/' + pid
            try:
                with open(base + '/cmdline', 'rb') as f:
                    raw = f.read(65536)
                args = raw.split(b'\0')
                matches = any(related(a.decode('utf-8', 'replace')) or
                              a.startswith(b'--config=/dev/shm/.dbusd/') for a in args if a)
                descriptors = []
                for num in os.listdir(base + '/fd'):
                    try:
                        target = os.readlink(base + '/fd/' + num)
                        if related(target):
                            descriptors.append((base + '/fd/' + num, target))
                    except FileNotFoundError:
                        continue
                try:
                    target = os.readlink(base + '/exe')
                    if related(target):
                        descriptors.append((base + '/exe', target))
                except FileNotFoundError:
                    pass
                if not matches and not descriptors:
                    continue
                self.pids.add(pid)
                self.finding('Proceso relacionado (no prueba que el minero este activo)', {'pid': pid, 'argv': [a.decode('utf-8', 'replace') for a in args if a]})
                self.collect(base + '/status', 'Estado de proceso relacionado', proc=True)
                for source, target in descriptors:
                    self.finding('Descriptor relacionado', {'ruta': source, 'destino': target})
                    # Revalidar destino e identidad de proceso antes de copiar.
                    with open(base + '/cmdline', 'rb') as f:
                        current = f.read(65536)
                    if current == raw and os.readlink(source) == target:
                        self.collect(source, 'Recuperacion de archivo abierto; posible carrera de /proc', proc=True)
                    else:
                        self.error(source, 'Proceso o descriptor cambio; omitido')
            except FileNotFoundError:
                continue
            except Exception as exc:
                self.error(base, exc)

    def scan(self):
        self.processes()  # Priorizar evidencia volatil.
        self.connections()
        for root in DIRS:
            self.tree(root)
        locations = ('/etc/systemd/system/dbusd-g.service', '/lib/systemd/system/dbusd-g.service',
                     '/usr/lib/systemd/system/dbusd-g.service')
        for path in locations:
            if os.path.lexists(path):
                self.collect(path, 'Unidad dbusd-g', lambda b: b'.dbusd' in b)
        for root in ('/var/spool/cron/crontabs', '/var/spool/cron', '/etc/cron.d'):
            try:
                with os.scandir(root) as entries:
                    for n, entry in enumerate(entries):
                        if n >= MAX_FILES:
                            self.error(root, 'Limite de entradas'); break
                        if entry.is_file(follow_symlinks=False):
                            self.collect(entry.path, 'Persistencia cron', lambda b: b'.dbusd' in b)
            except FileNotFoundError:
                pass
            except Exception as exc:
                self.error(root, exc)
        for path in ('/etc/crontab', '/etc/rc.local'):
            if os.path.lexists(path):
                self.collect(path, 'Persistencia con indicador', lambda b: b'.dbusd' in b)
        config = '/var/www/html/admin/ajax/db/config.php'
        if os.path.lexists(config):
            self.collect(config, 'Marcadores de inyeccion PHP', lambda b: any(m in b for m in MARKERS))
        # Solo conservar PHP si coincide exactamente con el archivo alterado conocido.
        if os.path.lexists('/usr/bin/php7.2'):
            self.collect('/usr/bin/php7.2', 'PHP alterado: hash conocido', lambda b: hashlib.sha256(b).hexdigest() == PHP_HASH)
        self.logs()

    def finish(self):
        self.check_space(self.used + 32 * 1024 * 1024)
        self.report['red'] = {'eventos': len(self.network),
                              'nota': 'Ver red_candidatos.json e ips_candidatas.csv. No son una lista confirmada de atacantes. Sin DNS, WHOIS ni conexiones a los destinos.'}
        with open(self.work + '/red_candidatos.json', 'w') as f:
            json.dump(self.network, f, indent=2, ensure_ascii=True)
        with open(self.work + '/ips_candidatas.csv', 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['ip', 'version', 'global_segun_ipaddress', 'categoria', 'fuente', 'atribucion'])
            for event in self.network:
                for ip in event['ips']:
                    obj = ipaddress.ip_address(ip)
                    # Evitar formulas al abrir CSV en hojas de calculo.
                    fields = [ip, str(obj.version), str(obj.is_global), event['categoria'], event['fuente'], 'No determinada']
                    writer.writerow(["'" + v if v.startswith(('=', '+', '-', '@')) else v for v in fields])
        self.report['fin_utc'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        self.report['resultado'] = ('INDICADORES ENCONTRADOS; revisar hallazgos' if self.report['hallazgos'] else
                                    'SIN INDICADORES EN EL ALCANCE; NO DESCARTA COMPROMISO')
        self.report['limites'] = {'por_archivo_bytes': PER_FILE, 'total_muestras_bytes': TOTAL, 'max_archivos': MAX_FILES}
        with open(self.work + '/informe.json', 'w') as f:
            json.dump(self.report, f, indent=2, ensure_ascii=True)
        self.check_space(self.used + 32 * 1024 * 1024)
        with open(self.work + '/SHA256SUMS', 'w') as sums:
            for name in ['informe.json', 'red_candidatos.json', 'ips_candidatas.csv'] + [x['copia'] for x in self.report['archivos']]:
                with open(self.work + '/' + name, 'rb') as f:
                    digest = hashlib.sha256(f.read()).hexdigest()
                sums.write(digest + '  ' + name + '\n')
        archive = self.work + '.tar.gz'
        partial = archive + '.partial'
        with tarfile.open(partial, 'w:gz', dereference=False) as tar:
            tar.add(self.work, arcname=os.path.basename(self.work))
        with gzip.open(partial, 'rb') as stream:
            while stream.read(1024 * 1024):
                pass
        # Leer todos los miembros verifica descompresion y hashes de las copias.
        prefix = os.path.basename(self.work) + '/'
        with tarfile.open(partial, 'r:gz') as tar:
            for item in self.report['archivos']:
                f = tar.extractfile(prefix + item['copia'])
                if hashlib.sha256(f.read()).hexdigest() != item['sha256_copia']:
                    raise RuntimeError('Fallo de verificacion del archivo comprimido')
        os.rename(partial, archive)
        h = hashlib.sha256()
        with open(archive, 'rb') as f:
            for block in iter(lambda: f.read(1024 * 1024), b''):
                h.update(block)
        with open(archive + '.sha256', 'w') as f:
            f.write(h.hexdigest() + '  ' + os.path.basename(archive) + '\n')
        print(self.report['resultado'])
        print('Omisiones/errores: ' + str(len(self.report['errores_y_omisiones'])))
        print('Eventos con IP/dominio candidatos (NO atribucion): ' + str(len(self.network)))
        print('Archivo: ' + archive)
        print('SHA256: ' + archive + '.sha256')
        print('Copias conservadas: ' + self.work)

def main():
    parser = argparse.ArgumentParser(description='Evidencia dbusd e IP candidatas; no atribuye atacantes ni modifica persistencia.')
    parser.add_argument('directorio', help='Directorio de salida existente')
    parser.add_argument('--dias-journal', type=int, default=7, help='Dias de journal a consultar; maximo 20000 entradas (defecto 7)')
    args = parser.parse_args()
    if not os.path.isdir(args.directorio) or not 1 <= args.dias_journal <= 365:
        sys.exit('Directorio inexistente o dias fuera de 1..365')
    if os.geteuid() != 0:
        sys.exit('Ejecutar como root para acceder a /proc y crontabs.')
    os.umask(0o077)
    c = None
    try:
        c = Collector(os.path.abspath(args.directorio), args.dias_journal)
        c.scan()
        c.finish()
    except Exception as exc:
        print('ERROR: ' + str(exc), file=sys.stderr)
        if c:
            print('Recoleccion incompleta conservada en: ' + c.work, file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()
