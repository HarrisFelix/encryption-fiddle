class MissingPublicKeyError(Exception):
    pass


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    if a == 0:
        return b, 0, 1
    else:
        g, x, y = extended_gcd(b % a, a)
        return g, y - (b // a) * x, x


def prime_factors(n):
    """https://stackoverflow.com/a/22808285"""
    i = 2
    factors = []

    while i * i <= n:
        if n % i:
            i += 1
        else:
            n //= i
            factors.append(i)
    if n > 1:
        factors.append(n)

    return factors


def phi(n):
    """https://stackoverflow.com/a/52263174"""
    totient = n

    for factor in prime_factors(n):
        totient -= totient // factor

    return totient


def coefficient_egcd_mod_p(e, p):
    _, y, _ = extended_gcd(e, p)

    return y % p


def inverse_mod(e, p):
    return pow(e, p - 2, p)


class Person:
    public_key = {}
    private_key = {}

    def __init__(self, name, certificate_tuple: tuple):
        self.name = f"_{name[:1]}"
        self.certificate = certificate_tuple

    def __repr__(self):
        try:
            key = f"(e{self.name},n{self.name})=({self.public_key['e']},{self.public_key['n']})"

            if self.private_key:
                key += f"\n(e{self.name},d{self.name})=({self.private_key['e']},{self.private_key['d']})"

            return key
        except KeyError:
            return f"(e{self.name},n{self.name})=(NULL,NULL)"

    def find_private_key(self):
        if not self.public_key:
            raise MissingPublicKeyError

        self.private_key["e"] = self.public_key["e"]
        self.private_key["d"] = coefficient_egcd_mod_p(self.public_key["e"], phi(self.public_key["n"]))
