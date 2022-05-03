from typing import List

from blocks import inv_sbox, rcon, sbox

NB = 4
NR = 10
NK = 4

Array = List[int]
Matrix = List[Array]

def encrypt(input_bytes: Array, key: str) -> Array:
    """Encriptar un conjunto de bytes dependiendo una clave

    Args:
        input_bytes (Array): Entrada de datos en formato de lista
        key (str): Clave con la que se encriptaran los datos

    Returns:
        Array: Lista de numeros despues de aplicar las rondas
    """
    state: Matrix = [[] for _ in range(4)] # Matriz de estados
    for r in range(4):
        for c in range(NB):
            state[r].append(input_bytes[r + 4 * c])
    key_schedule = key_expansion(key)
    state = add_round_key(state, key_schedule)
    for rnd in range(1, NR):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, key_schedule, rnd)
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, key_schedule, NR)
    output: Array = [0 for _ in range(4 * NB)]
    for r in range(4):
        for c in range(NB):
            output[r + 4 * c] = state[r][c]
    return output


def decrypt(cipher: Array, key: str) -> Array:
    """Desencriptar un arreglo de enteros

    Args:
        cipher (Array): Bytes para desencriptar
        key (str): Clave para desencriptar

    Returns:
        Array: Arreglo de enteros con los bits ya desencriptados
    """ 
    state: Matrix = [[] for _ in range(NB)]
    for r in range(4):
        for c in range(NB):
            state[r].append(cipher[r + 4 * c])
    key_schedule = key_expansion(key)
    state = add_round_key(state, key_schedule, NR)
    rnd = NR - 1
    while rnd >= 1:
        state = shift_rows(state, inv=True)
        state = sub_bytes(state, inv=True)
        state = add_round_key(state, key_schedule, rnd)
        state = mix_columns(state, inv=True)
        rnd -= 1
    state = shift_rows(state, inv=True)
    state = sub_bytes(state, inv=True)
    state = add_round_key(state, key_schedule, rnd)
    output: Array = [0 for _ in range(4 * NB)]
    for r in range(4):
        for c in range(NB):
            output[r + 4 * c] = state[r][c]
    return output


def sub_bytes(state: Matrix, inv: bool = False):
    box = sbox if not inv else inv_sbox
    for i, row in enumerate(state):
        for j, value in enumerate(row):
            state[i][j] = box[16 * (value // 0x10) + (value % 0x10)]
    return state


def shift_rows(state: Matrix, inv: bool = False):
    count = 1
    if inv == False:
        for i in range(1, NB):
            state[i] = left_shift(state[i], count)
            count += 1
    else:
        for i in range(1, NB):
            state[i] = right_shift(state[i], count)
            count += 1
    return state


def mix_columns(state: Matrix, inv: bool = False) -> Matrix:
    for i in range(NB):
        if not inv:
            s0: int = (
                mul_by_02(state[0][i])
                ^ mul_by_03(state[1][i])
                ^ state[2][i]
                ^ state[3][i]
            )
            s1: int = (
                state[0][i]
                ^ mul_by_02(state[1][i])
                ^ mul_by_03(state[2][i])
                ^ state[3][i]
            )
            s2: int = (
                state[0][i]
                ^ state[1][i]
                ^ mul_by_02(state[2][i])
                ^ mul_by_03(state[3][i])
            )
            s3: int = (
                mul_by_03(state[0][i])
                ^ state[1][i]
                ^ state[2][i]
                ^ mul_by_02(state[3][i])
            )
        else:  # decryption
            s0: int = (
                mul_by_0e(state[0][i])
                ^ mul_by_0b(state[1][i])
                ^ mul_by_0d(state[2][i])
                ^ mul_by_09(state[3][i])
            )
            s1: int = (
                mul_by_09(state[0][i])
                ^ mul_by_0e(state[1][i])
                ^ mul_by_0b(state[2][i])
                ^ mul_by_0d(state[3][i])
            )
            s2: int = (
                mul_by_0d(state[0][i])
                ^ mul_by_09(state[1][i])
                ^ mul_by_0e(state[2][i])
                ^ mul_by_0b(state[3][i])
            )
            s3: int = (
                mul_by_0b(state[0][i])
                ^ mul_by_0d(state[1][i])
                ^ mul_by_09(state[2][i])
                ^ mul_by_0e(state[3][i])
            )
        state[0][i] = s0
        state[1][i] = s1
        state[2][i] = s2
        state[3][i] = s3
    return state


def key_expansion(key: str) -> Matrix:
    key_symbols = [ord(symbol) for symbol in key]
    if len(key_symbols) < 4 * NK:
        for _ in range(4 * NK - len(key_symbols)):
            key_symbols.append(0x01)
    key_schedule: Matrix = [[] for _ in range(4)]
    for r in range(4):
        for c in range(NK):
            key_schedule[r].append(key_symbols[r + 4 * c])
    for col in range(NK, NB * (NR + 1)):
        if col % NK == 0:
            tmp = [key_schedule[row][col - 1] for row in range(1, 4)]
            tmp.append(key_schedule[0][col - 1])
            for i, value in enumerate(tmp):
                sbox_row = value // 0x10
                sbox_col = tmp[i] % 0x10
                sbox_elem = sbox[16 * sbox_row + sbox_col]
                tmp[i] = sbox_elem
            for row in range(4):
                s = (
                    (key_schedule[row][col - 4])
                    ^ (tmp[row])
                    ^ (rcon[row][int(col / NK - 1)])
                )
                key_schedule[row].append(s)
        else:
            for row in range(4):
                s = key_schedule[row][col - 4] ^ key_schedule[row][col - 1]
                key_schedule[row].append(s)
    return key_schedule


def add_round_key(
    state: Matrix, key_schedule: Matrix, round: int = 0
) -> Matrix:
    for col in range(NK):
        s0 = state[0][col] ^ key_schedule[0][NB * round + col]
        s1 = state[1][col] ^ key_schedule[1][NB * round + col]
        s2 = state[2][col] ^ key_schedule[2][NB * round + col]
        s3 = state[3][col] ^ key_schedule[3][NB * round + col]
        state[0][col] = s0
        state[1][col] = s1
        state[2][col] = s2
        state[3][col] = s3
    return state


def left_shift(array: Array, count: int) -> Array:
    res = array[:]
    for _ in range(count):
        temp = res[1:]
        temp.append(res[0])
        res[:] = temp[:]
    return res


def right_shift(array: Array, count: int):
    res = array[:]
    for _ in range(count):
        tmp = res[:-1]
        tmp.insert(0, res[-1])
        res[:] = tmp[:]
    return res


def mul_by_02(num: int) -> int:
    res = num << 1 if num < 0x80 else (num << 1) ^ 0x1B
    return res % 0x100


def mul_by_03(num: int) -> int:
    return mul_by_02(num) ^ num


def mul_by_09(num: int) -> int:
    return mul_by_02(mul_by_02(mul_by_02(num))) ^ num


def mul_by_0b(num: int) -> int:
    return mul_by_02(mul_by_02(mul_by_02(num))) ^ mul_by_02(num) ^ num


def mul_by_0d(num: int) -> int:
    return mul_by_02(mul_by_02(mul_by_02(num))) ^ mul_by_02(mul_by_02(num)) ^ num


def mul_by_0e(num: int) -> int:
    return (
        mul_by_02(mul_by_02(mul_by_02(num)))
        ^ mul_by_02(mul_by_02(num))
        ^ mul_by_02(num)
    )
