from utils import inverse_mod


class NotOnTheSameCurveError(Exception):
    pass


class NotAnEllipticalPointError(Exception):
    pass


class DoesntBelongToCurveError(Exception):
    pass


class EllipticalCurve:
    def __init__(self, a: int, b: int, p: int):
        self.a = a
        self.b = b
        self.p = p

    def __eq__(self, other):
        return self.a == other.a and self.b == other.b and self.p == other.p

    def __repr__(self):
        return f"y\N{SUPERSCRIPT TWO} = x\N{SUPERSCRIPT THREE} + {self.a}x + {self.b} mod {self.p}"

    def value_at_x(self, x: int) -> int:
        return (pow(x, 3) + (self.a * x) + self.b) % self.p

    def x_solutions(self, x: int) -> bool | int:
        return self.modular_sqrt(self.value_at_x(x), self.p)

    def cardinal(self) -> int:
        """https://en.wikipedia.org/wiki/Counting_points_on_elliptic_curves#Naive_approach"""
        result = 2

        for x in range(self.p):
            if self.x_solutions(x):
                result += 2

        return result

    @staticmethod
    def modular_sqrt(a: int, p: int) -> int:
        """https://gist.github.com/nakov/60d62bdf4067ea72b7832ce9f71ae079"""

        def legendre_symbol(a_bis: int, p_bis: int) -> int:
            ls = pow(a_bis, (p_bis - 1) // 2, p_bis)
            return -1 if ls == p_bis - 1 else ls

        if legendre_symbol(a, p) != 1:
            return 0
        elif a == 0:
            return 0
        elif p == 2:
            return p
        elif p % 4 == 3:
            return pow(a, (p + 1) // 4, p)

        s = p - 1
        e = 0
        while s % 2 == 0:
            s //= 2
            e += 1

        n = 2
        while legendre_symbol(n, p) != -1:
            n += 1

        x = pow(a, (s + 1) // 2, p)
        b = pow(a, s, p)
        g = pow(n, s, p)
        r = e

        while True:
            t = b
            m = 0
            for m in range(r):
                if t == 1:
                    break
                t = pow(t, 2, p)

            if m == 0:
                return x

            gs = pow(g, 2 ** (r - m - 1), p)
            g = (gs * gs) % p
            x = (x * gs) % p
            b = (b * g) % p
            r = m


class EllipticalPoint:
    def __init__(self, x: int | None, y: int | None, curve: EllipticalCurve):
        self.x = x
        self.y = y
        self.curve = curve

    def __eq__(self, other):
        if not isinstance(other, EllipticalPoint):
            raise NotAnEllipticalPointError
        if not self.curve == other.curve:
            raise NotOnTheSameCurveError
        return self.x == other.x and self.y == other.y

    def __add__(self, other):
        """https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication"""
        if isinstance(other, PointAtInfinity):
            return self

        if self == other:
            s = (3 * pow(self.x, 2) + self.curve.a) * inverse_mod(2 * self.y, self.curve.p)
        else:
            inv_mod = inverse_mod(other.x - self.x, self.curve.p)

            if not inv_mod:
                return PointAtInfinity(self.curve)

            s = (other.y - self.y) * inv_mod

        x = pow(s, 2) - self.x - other.x
        y = (s * (self.x - x)) - self.y

        return EllipticalPoint(x % self.curve.p, y % self.curve.p, self.curve)

    def __mul__(self, scalar: int):
        """https://onyb.gitbook.io/secp256k1-python/scalar-multiplication-in-python"""
        tmp = self
        result = PointAtInfinity(self.curve)

        while scalar:
            if scalar & 1:
                result = result + tmp
            tmp = tmp + tmp
            scalar >>= 1

        return result

    def __rmul__(self, scalar: int):
        return self * scalar

    def __repr__(self):
        return f"({self.x},{self.y})"

    @staticmethod
    def create_point_from_x(x: int, curve: EllipticalCurve):
        y = curve.x_solutions(x)

        if not y:
            return None
        else:
            return EllipticalPoint(x, y, curve), EllipticalPoint(x, curve.p - y, curve)

    def find_n_in_np(self, np) -> int:
        n = 1

        while (n * self).x != np.x:
            n += 1

        return n

    def find_order(self) -> int:
        order = 1
        o = PointAtInfinity(self.curve)

        while order * self != o:
            order += 1

        return order


class PointAtInfinity(EllipticalPoint):
    def __init__(self, curve):
        super().__init__(None, None, curve)

    def __repr__(self):
        return "O"

    def __add__(self, other):
        return other
