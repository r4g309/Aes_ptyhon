from os import listdir, name, remove, system
from os.path import abspath, basename, dirname, exists, isfile, join
from signal import SIGINT, signal
from sys import exit as _exit
from sys import stderr

from colorama import Fore, init
from simple_term_menu import TerminalMenu

from aes128 import decrypt, encrypt


def signal_handler(sig, frame):
    """Funcion que atrapara la combinacion de teclas <Ctrl-c>
    Args:
        sig (int)
        frame (frame)
    """
    stderr.write(f"{Fore.RED}Saliendo...")
    exit(1)


def list_files(directory: str = "."):
    full_path = abspath(directory)
    while True:
        if isfile(full_path):
            return full_path
        files = listdir(full_path)
        files.insert(0, "..")
        terminal = TerminalMenu(files, title=f"Path: {full_path}")
        opcion: int = terminal.show()  # type:ignore
        if isfile(files[opcion]):
            return abspath(files[opcion])
        if opcion == 0:
            full_path = dirname(full_path)
        else:
            full_path = join(full_path, files[opcion])


def convert_data(data, key, aes_function):
    """Encripta o desencripta una cadena de bytes que son pasados por parámetro

    Args:
        data (bytes): Bytes que se desean encriptar
        key (str): Clave necesaria para desencriptar o encriptar los datos
        aes_function (function): Dependiendo la funcion, se encriptara o desencriptara

    Returns:
        list[int]: Lista con los bytes ya encriptados/desencriptados
    """
    part_enc = []
    all_data = []
    data = [data[i: i + 16] for i in range(0, len(data), 16)]
    for slice in data:
        slice = list(slice)
        if len(slice) < 16:
            empty_spaces = 16 - len(slice) - 1
            slice.extend(
                [0 if i != empty_spaces else 1 for i in range(
                    empty_spaces + 1)]
            )
        part_enc = aes_function(slice, key)
        all_data.extend(part_enc)
    return all_data


def save_data(data, out_path, text):
    """Guarda un array de bits en un archivo

    Args:
        data (Matrix): Bits a escribir
        out_path (str): Path del archivo original
        text (str): Texto a añadir en el nombre del archivo
    """
    out_path = join(dirname(out_path), text + basename(out_path))
    if exists(out_path):
        option = input(
            f"{Fore.YELLOW}Se encontro otro archivo con el path {basename(out_path)},¿Desea eliminarlo?(s/n){Fore.RESET}"
        ).lower()
        if option == "s":
            remove(out_path)
        else:
            print(f"{Fore.GREEN}No se modifico el archivo{Fore.RESET}")
            input()
            return
    with open(out_path, "xb") as f:
        f.write(bytes(data))


def read_file(abs_path):
    """Retorna el contenido en bytes de un archivo

    Args:
        abs_path (str): Path del archivo

    Returns:
        List[int]: Bytes del archivo
    """
    with open(abs_path, "rb") as f:
        data = f.read()
    return data


def clean_data(data):
    """Elimina los bytes que se utilizan al final de la encriptacion para lograr asi completar los 16 bites

    Args:
        data (List[int]): Bytes a limpiar luego de desencriptarlos

    Returns:
        List[int]: Datos limpios
    """
    for byte in data[::-1]:
        if byte == 0 or byte == 1:
            data.pop()
    return data


def get_key():
    """Retorna una clave con una longitug no mayor a 16 caracteres ademas que se usan caracteres ascii menores a 255

    Returns:
        str: Clave valida para encriptar archivos
    """
    while True:
        key = input(
            f"{Fore.MAGENTA}Ingrese su clave de encriptacion/desencriptacion.\n"
            f"La clave tiene que ser de menos de 16 simbolos.{Fore.RED}"
            f"Por favor,NO LA OLVIDE!{Fore.BLUE}\n>>> {Fore.RESET}"
        )
        if len(key) > 16:
            print(f"{Fore.RED}Clave muy larga,Imagine otra.{Fore.RESET}")
            continue
        if any([ord(symbol) > 0xFF for symbol in key]):
            print(
                f"{Fore.GREEN}Ingrese otra clave :D,Lamentamos las molestias.{Fore.RESET}"
            )
            continue
        break
    return key


def main():
    while True:
        system("cls" if name == "nt" else "clear")
        option = TerminalMenu(
            ["[1]Encriptar", "[2]Desencriptar", "[3]Salir"],
            title="Encriptador AES",
        ).show()
        match option:
            case 0:
                path_of_file = list_files()
                data = read_file(path_of_file)
                key = get_key()
                data = convert_data(data, key, encrypt)
                save_data(data, path_of_file, "encryp_")
            case 1:
                path_of_file = list_files()
                data = read_file(path_of_file)
                key = get_key()
                data = convert_data(data, "hola", decrypt)
                data = clean_data(data)
                save_data(data, path_of_file, "decrypt_")
            case 2:
                print(f"{Fore.GREEN}Saliendo con exito")
                _exit(0)


if __name__ == "__main__":
    init()
    signal(SIGINT, signal_handler)
    main()
