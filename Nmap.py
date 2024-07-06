import nmap

def escanear(anfitrion, puertos, argumentos, ejecutar_como_superusuario):
    nm = nmap.PortScanner()
    puertos = ",".join(puertos)  # Unir la lista en una cadena
    if ejecutar_como_superusuario:
        nm.scan(hosts=anfitrion, ports=puertos, arguments=argumentos + ' -O -sV --script=default', sudo=True)
    else:
        nm.scan(hosts=anfitrion, ports=puertos, arguments=argumentos + ' -O -sV --script=default')

    for anfitrion in nm.all_hosts():
        print(f"Anfitrión : {anfitrion} ({nm[anfitrion].hostname()})")
        print(f"Estado : {nm[anfitrion].state()}")
        for osmatch in nm[anfitrion]['osmatch']:
            print("----------")
            print('OsMatch.name : {0}'.format(osmatch['name']))
            print('OsMatch.accuracy : {0}'.format(osmatch['accuracy']))
            print('OsMatch.line : {0}'.format(osmatch['line']))
            for osclass in osmatch['osclass']:
                print('OsClass.type : {0}'.format(osclass['type']))
                print('OsClass.vendor : {0}'.format(osclass['vendor']))
                print('OsClass.osfamily : {0}'.format(osclass['osfamily']))
                print('OsClass.osgen : {0}'.format(osclass['osgen']))
                print('OsClass.accuracy : {0}'.format(osclass['accuracy']))
        for protocolo in nm[anfitrion].all_protocols():
            print("----------")
            print(f"Protocolo : {protocolo}")
            print("----------")

            lport = nm[anfitrion][protocolo].keys()
            for puerto in lport:
                print(f"Puerto : {puerto}\tEstado : {nm[anfitrion][protocolo][puerto]['state']}")
                print(f"Nombre : {nm[anfitrion][protocolo][puerto]['name']}")
                print(f"Producto : {nm[anfitrion][protocolo][puerto]['product']}")
                print(f"Versión : {nm[anfitrion][protocolo][puerto]['version']}")
                print(f"Información adicional : {nm[anfitrion][protocolo][puerto]['extrainfo']}")
                print(f"Conf : {nm[anfitrion][protocolo][puerto]['conf']}")
                print(f"Cpe : {nm[anfitrion][protocolo][puerto]['cpe']}")
                print("----------")

def main():
    # Solicitar al usuario los hosts
    anfitrion = input("Ingrese los anfitriones (por ejemplo, '192.168.1.1' o '192.168.1.0/24'): ")

    # Solicitar al usuario los puertos
    puertos = input("Ingrese los puertos (por ejemplo, '22,80' o '1-1000'): ").split(",")

    # Solicitar al usuario los argumentos adicionales
    argumentos = input("Ingrese argumentos adicionales para nmap (por ejemplo, '-sS' para un escaneo SYN): ")

    # Solicitar al usuario si desea ejecutar como superusuario
    ejecutar_como_superusuario = input("¿Desea ejecutar como superusuario? (s/n): ").strip().lower() == 's'

    # Ejecutar el escaneo
    escanear(anfitrion, puertos, argumentos, ejecutar_como_superusuario)

if __name__ == '__main__':
    main()
