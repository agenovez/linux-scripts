#!/usr/bin/env python3
"""Recoleccion acotada de indicadores dbusd. Python 3.6+, Linux, ejecutar como root.
Uso: sudo python3 verificar_dbusd.py /ruta/existente/con/espacio
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
    def __init__(self, output):
        self.output = output
        self.check_space(192 * 1024 * 1024)
        self.work = tempfile.mkdtemp(prefix='evidencias-dbusd-' + time.strftime('%Y%m%d-%H%M%S-'), dir=output)
        os.mkdir(self.work + '/muestras', 0o700)
        self.used = 0
        self.count = 0
        self.report = {'host': socket.gethostname(), 'inicio_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                       'hallazgos': [], 'archivos': [], 'errores_y_omisiones': [],
                       'alcance': 'Indicadores conocidos dbusd; sin busqueda global ni logs generales. Ausencia no descarta compromiso. Las lecturas pueden actualizar atime. Herramientas y kernel locales no son una fuente independiente de confianza.'}

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

    def finish(self):
        self.report['fin_utc'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        self.report['resultado'] = ('INDICADORES ENCONTRADOS; revisar hallazgos' if self.report['hallazgos'] else
                                    'SIN INDICADORES EN EL ALCANCE; NO DESCARTA COMPROMISO')
        self.report['limites'] = {'por_archivo_bytes': PER_FILE, 'total_muestras_bytes': TOTAL, 'max_archivos': MAX_FILES}
        with open(self.work + '/informe.json', 'w') as f:
            json.dump(self.report, f, indent=2, ensure_ascii=True)
        self.check_space(self.used + 32 * 1024 * 1024)
        with open(self.work + '/SHA256SUMS', 'w') as sums:
            for name in ['informe.json'] + [x['copia'] for x in self.report['archivos']]:
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
        print('Archivo: ' + archive)
        print('SHA256: ' + archive + '.sha256')
        print('Copias conservadas: ' + self.work)

def main():
    if len(sys.argv) != 2 or not os.path.isdir(sys.argv[1]):
        sys.exit('Uso: sudo python3 verificar_dbusd.py /directorio/existente')
    if os.geteuid() != 0:
        sys.exit('Ejecutar como root para acceder a /proc y crontabs.')
    os.umask(0o077)
    c = None
    try:
        c = Collector(os.path.abspath(sys.argv[1]))
        c.scan()
        c.finish()
    except Exception as exc:
        print('ERROR: ' + str(exc), file=sys.stderr)
        if c:
            print('Recoleccion incompleta conservada en: ' + c.work, file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()
