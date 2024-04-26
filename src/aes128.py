from hashlib import sha256
from typing import Generator
from utils import Person


class InvalidKeyBitCountError(Exception):
    pass


class AES128:
    """https://en.wikipedia.org/wiki/Advanced_Encryption_Standard"""
    """https://gist.github.com/bonsaiviking/5571001"""
    round_constant = (0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a)

    s_box = (0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
             0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
             0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
             0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
             0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
             0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
             0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
             0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
             0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
             0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
             0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
             0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
             0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
             0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
             0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
             0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16)

    inv_s_box = (0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
                 0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
                 0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
                 0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
                 0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
                 0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
                 0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
                 0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
                 0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
                 0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
                 0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
                 0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
                 0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
                 0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
                 0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
                 0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D)

    fixed_matrix = (2, 3, 1, 1,
                    1, 2, 3, 1,
                    1, 1, 2, 3,
                    3, 1, 1, 2)

    inv_fixed_matrix = (14, 11, 13, 9,
                        9, 14, 11, 13,
                        13, 9, 14, 11,
                        11, 13, 9, 14)

    def __init__(self, key: str):
        self.key = self.convert_hex_string_to_tuple(key)

        if len(self.key) != 16:
            raise InvalidKeyBitCountError

        self.state = []

        self.nb = 4
        self.nr = 10
        self.nk = 4

    def __repr__(self):
        key = f"⌈ {hex(self.key[0])} {hex(self.key[4])} {hex(self.key[8])} {hex(self.key[12])} ⌉\n"
        key += f"│ {hex(self.key[1])} {hex(self.key[5])} {hex(self.key[9])} {hex(self.key[13])} │\n"
        key += f"│ {hex(self.key[2])} {hex(self.key[6])} {hex(self.key[10])} {hex(self.key[14])} │\n"
        key += f"⌊ {hex(self.key[3])} {hex(self.key[7])} {hex(self.key[11])} {hex(self.key[15])} ⌋"

        return ''.join(char if char == 'x' else char.upper() for char in key)

    def encrypt(self, clear_text: str) -> str:
        cipher_text = ""
        clear_text = ''.join([self.standardize_hex(hex(ord(hexa))) for hexa in clear_text])

        while len(clear_text) % 16:
            clear_text += "0"

        blocks = [clear_text[i:i + 32] for i in range(0, len(clear_text), 32)]

        for i, block in enumerate(blocks):
            previous_block = ""

            if i > 0:
                previous_block = self.int_list_to_hex_string(self.state)
            cipher_text += self.encrypt_block(block, previous_block)

        return cipher_text

    def encrypt_block(self, block: str, previous_cipher: str = "") -> str:
        block = [block[i:i + 2] for i in range(0, len(block), 2)]

        n = self.nb * 4
        self.state = [int(char, 16) for char in block]

        if previous_cipher:
            self.state = self.xor(self.convert_hex_string_to_tuple(previous_cipher), self.state)

        keys = self.key_schedule()
        self.add_round_key(keys[0:n])

        for r in range(1, self.nr):
            self.sub_bytes()
            self.shift_rows()
            self.mix_columns()
            k = keys[r * n:(r + 1) * n]
            self.add_round_key(k)

        self.sub_bytes()
        self.shift_rows()
        self.add_round_key(keys[self.nr * n:])

        return self.int_list_to_hex_string(self.state)

    def decrypt(self, cipher_text: str) -> str:
        clear_text = ""
        blocks = [cipher_text[i:i + 32] for i in range(0, len(cipher_text), 32)]

        for i, block in enumerate(blocks):
            previous_block = ""

            if i > 0:
                previous_block = blocks[i - 1]
            clear_text += self.decrypt_block(block, previous_block)

        return clear_text

    def decrypt_block(self, block: str, previous_cipher: str = "") -> str:
        block = [block[i:i + 2] for i in range(0, len(block), 2)]

        n = self.nb * 4
        self.state = [int(char, 16) for char in block]

        keys = self.key_schedule()
        k = keys[self.nr * n:(self.nr + 1) * n]
        self.add_round_key(k)

        for r in range(self.nr - 1, 0, -1):
            self.inv_shift_rows()
            self.inv_sub_bytes()
            k = keys[r * n:(r + 1) * n]
            self.add_round_key(k)
            self.inv_mix_columns()

        self.inv_shift_rows()
        self.inv_sub_bytes()
        self.add_round_key(keys[0:n])

        if previous_cipher:
            self.state = self.xor(self.convert_hex_string_to_tuple(previous_cipher), self.state)

        while not self.state[-1]:
            self.state.pop(-1)

        return "".join(map(chr, self.state))

    @staticmethod
    def standardize_hex(hexa: str) -> str:
        if len(hexa) == 3:
            return "0" + hexa[2]
        else:
            return hexa[2:]

    def int_list_to_hex_string(self, int_list: list[int]) -> str:
        hex_string = ""

        for e in int_list:
            hex_string += self.standardize_hex(hex(e))

        return hex_string

    @staticmethod
    def convert_hex_string_to_tuple(hex_str: str) -> tuple[int]:
        hex_list = [hex_str.replace(" ", "")[i:i + 2] for i in range(0, len(hex_str.replace(" ", "")), 2)]

        return tuple([int(hex_char, 16) for hex_char in hex_list])

    @staticmethod
    def xor(x, y) -> list:
        return [a ^ b for a, b in zip(x, y)]

    @staticmethod
    def rot_word(word: list) -> list:
        return word[1:] + word[:1]

    def sub_word(self, word: list) -> Generator[int, int, None]:
        return (self.s_box[b] for b in word)

    def key_schedule(self):
        expanded_key = []
        expanded_key.extend(self.key)

        for i in range(self.nk, self.nb * (self.nr + 1)):
            tmp = expanded_key[(i - 1) * 4:i * 4]

            if i % self.nk == 0:
                tmp = self.xor(self.sub_word(self.rot_word(tmp)), (self.round_constant[i // self.nk], 0, 0, 0))
            elif self.nk > 6 and i % self.nk == 4:
                tmp = self.sub_word(tmp)

            expanded_key.extend(self.xor(tmp, expanded_key[(i - self.nk) * 4:(i - self.nk + 1) * 4]))

        return expanded_key

    @staticmethod
    def index_from_hex(hexa: int) -> tuple[int, int]:
        return hexa // 16, hexa % 16

    def value_from_hex(self, hexa: int, array: tuple) -> int:
        y, x = self.index_from_hex(hexa)

        return array[y * 0x10 + x]

    def sub_bytes(self):
        for i, e in enumerate(self.state):
            self.state[i] = self.value_from_hex(e, self.s_box)

    def inv_sub_bytes(self):
        for i, e in enumerate(self.state):
            self.state[i] = self.value_from_hex(e, self.inv_s_box)

    def shift_a_row_left(self, row):
        self.state[row], self.state[row + 4], self.state[row + 8], self.state[row + 12] = self.state[row + 4], \
            self.state[row + 8], \
            self.state[row + 12], \
            self.state[row]

    def inv_shift_a_row_left(self, row):
        self.state[row], self.state[row + 4], self.state[row + 8], self.state[row + 12] = self.state[row + 12], \
            self.state[row], \
            self.state[row + 4], \
            self.state[row + 8]

    def shift_rows(self):
        for row in range(1, 4):
            for _ in range(row):
                self.shift_a_row_left(row)

    def inv_shift_rows(self):
        for row in range(1, 4):
            for _ in range(row):
                self.inv_shift_a_row_left(row)

    @staticmethod
    def gmul(x: int, y: int) -> int:
        result = 0

        for _ in range(8):
            if y & 1:
                result ^= x
            x <<= 1

            if x & 0x100:
                x ^= 0x11b

            y >>= 1

        return result

    def mix_columns(self):
        """https://en.wikipedia.org/wiki/Rijndael_MixColumns"""
        s = list(self.state)
        m = self.fixed_matrix

        for i in range(0, 16, 4):
            self.state[i] = (self.gmul(m[0], s[i]) ^ self.gmul(m[1], s[i + 1]) ^
                             self.gmul(m[2], s[i + 2]) ^ self.gmul(m[3], s[i + 3]))
            self.state[i + 1] = (self.gmul(m[4], s[i]) ^ self.gmul(m[5], s[i + 1]) ^ self.gmul(m[6], s[i + 2]) ^
                                 self.gmul(m[7], s[i + 3]))
            self.state[i + 2] = (self.gmul(m[8], s[i]) ^ self.gmul(m[9], s[i + 1]) ^
                                 self.gmul(m[10], s[i + 2]) ^ self.gmul(m[11], s[i + 3]))
            self.state[i + 3] = (self.gmul(m[12], s[i]) ^ self.gmul(m[13], s[i + 1]) ^
                                 self.gmul(m[14], s[i + 2]) ^ self.gmul(m[15], s[i + 3]))

    def inv_mix_columns(self):
        """https://en.wikipedia.org/wiki/Rijndael_MixColumns"""
        s = list(self.state)
        m = self.inv_fixed_matrix

        for i in range(0, 16, 4):
            self.state[i] = (self.gmul(m[0], s[i]) ^ self.gmul(m[1], s[i + 1]) ^
                             self.gmul(m[2], s[i + 2]) ^ self.gmul(m[3], s[i + 3]))
            self.state[i + 1] = (self.gmul(m[4], s[i]) ^ self.gmul(m[5], s[i + 1]) ^ self.gmul(m[6], s[i + 2]) ^
                                 self.gmul(m[7], s[i + 3]))
            self.state[i + 2] = (self.gmul(m[8], s[i]) ^ self.gmul(m[9], s[i + 1]) ^
                                 self.gmul(m[10], s[i + 2]) ^ self.gmul(m[11], s[i + 3]))
            self.state[i + 3] = (self.gmul(m[12], s[i]) ^ self.gmul(m[13], s[i + 1]) ^
                                 self.gmul(m[14], s[i + 2]) ^ self.gmul(m[15], s[i + 3]))

    def add_round_key(self, round_key):
        """Symmetric pour decrypter."""
        for i, e in enumerate(round_key):
            self.state[i] = e ^ self.state[i]


class RSA:
    def __init__(self, message_to_crypt):
        self.message_to_crypt = message_to_crypt
        self.encrypted_message = []

    def __repr__(self):
        return str(self.encrypted_message).replace(" ", "").replace("'", "")[1:-1]

    def encrypt(self, person: Person):
        sha = sha256(self.message_to_crypt.encode()).hexdigest()
        decimal = self.hex_lst_to_dec_lst(self.split(sha))
        self.encrypted_message = self.rsa_cipher(decimal, person.private_key["d"], person.public_key["n"])

    @staticmethod
    def fast_modular_exponentiation(b, exp, mod):
        """https://stackoverflow.com/questions/57668289/implement-the-function-fast-modular-exponentiation"""
        result = 1

        while exp > 1:
            if exp & 1:
                result = (result * b) % mod

            b = b ** 2 % mod
            exp >>= 1

        return (b * result) % mod

    @staticmethod
    def split(block_str: str) -> list[str]:
        block_lst = len(block_str) // 6

        if len(block_str) % 6 != 0:
            block_lst += 1

        lst = ["0"] * block_lst

        for i in range(len(block_str)):
            if i % 6 == 0:
                lst[i // 6] = block_str[i]
            else:
                lst[i // 6] = lst[i // 6] + block_str[i]

        if len(block_str) % 6 != 0:
            lst[-1] = lst[-1] + "0" * (6 - len(block_str) % 6)

        return lst

    @staticmethod
    def hex_lst_to_dec_lst(lst: list):
        if len(lst) == 1:
            return int(lst[0], base=16)

        for i in range(len(lst)):
            lst[i] = int(lst[i], base=16)

        return lst

    def rsa_cipher(self, lst, d_key, mod):
        if len(lst) == 1:
            return self.fast_modular_exponentiation(lst[0], d_key, mod)

        for i in range(len(lst)):
            lst[i] = self.fast_modular_exponentiation(lst[i], d_key, mod)

        return lst
