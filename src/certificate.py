class AuthorityCertificate:
    def __init__(self, string: str):
        self.public_key = self.public_key_from_str(string)

    def __repr__(self):
        return f"(e_AC,n_AC)=({self.public_key['e']},{self.public_key['n']}))"

    @staticmethod
    def public_key_from_str(string: str):
        return {"e": int(string[5:9]), "n": int(string[16:])}

    def decrypt_certificate(self, certificate: tuple[int]) -> str:
        blocks = []

        for block in certificate:
            tmp = pow(block, self.public_key["e"], self.public_key["n"])
            letter_1 = tmp // 256
            letter_2 = letter_1 % 256
            letter_3 = tmp % 256

            while letter_1 > 128:
                tmp = letter_1
                letter_1 = tmp // 256
                letter_2 = tmp % 256

            blocks.append(letter_1)
            blocks.append(letter_2)
            blocks.append(letter_3)

        public_key = ""

        for b in blocks:
            public_key += chr(b)

        return public_key
