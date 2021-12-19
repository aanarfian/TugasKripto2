from os import urandom
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional,Callable,Tuple
import random
from binascii import hexlify

def egcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = egcd(b % a, a)
        return g, x - (b // a) * y, y

def modinv(a, m):
    a = a % m
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception("modular inverse tidak ada")
    else:
        return x % m

def modsqrt(a, p):
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

def legendre_symbol(a, p):
    ls = pow(a, (p - 1) // 2, p)
    return -1 if ls == p - 1 else ls


def int_length_in_byte(n: int):
    assert n >= 0
    length = 0
    while n:
        n >>= 8
        length += 1
    return length

@dataclass
class Point:
    x: Optional[int]
    y: Optional[int]
    curve: "Curve"

    def is_at_infinity(self) -> bool:
        return self.x is None and self.y is None

    def __post_init__(self):
        if not self.is_at_infinity() and not self.curve.is_on_curve(self):
            raise ValueError("The point is not on the curve.")

    def __str__(self):
        if self.is_at_infinity():
            return f"Point(At infinity, Curve={str(self.curve)})"
        else:
            return f"Point(X={self.x}, Y={self.y}, Curve={str(self.curve)})"

    def __repr__(self):
        return self.__str__()

    def __eq__(self, other):
        return self.curve == other.curve and self.x == other.x and self.y == other.y

    def __neg__(self):
        return self.curve.neg_point(self)

    def __add__(self, other):
        return self.curve.add_point(self, other)

    def __radd__(self, other):
        return self.__add__(other)

    def __sub__(self, other):
        negative = - other
        return self.__add__(negative)

    def __mul__(self, scalar: int):
        return self.curve.mul_point(scalar, self)

    def __rmul__(self, scalar: int):
        return self.__mul__(scalar)


@dataclass
class Curve(ABC):
    name: str
    a: int
    b: int
    p: int
    n: int
    G_x: int
    G_y: int

    def __str__(self):
        return self.name

    def __repr__(self):
        return self.__str__()

    def __eq__(self, other):
        return (
            self.a == other.a and self.b == other.b and self.p == other.p and
            self.n == other.n and self.G_x == other.G_x and self.G_y == other.G_y
        )

    @property
    def G(self) -> Point:
        return Point(self.G_x, self.G_y, self)

    @property
    def INF(self) -> Point:
        return Point(None, None, self)

    def is_on_curve(self, P: Point) -> bool:
        if P.curve != self:
            return False
        return P.is_at_infinity() or self._is_on_curve(P)

    @abstractmethod
    def _is_on_curve(self, P: Point) -> bool:
        pass

    def add_point(self, P: Point, Q: Point) -> Point:
        if (not self.is_on_curve(P)) or (not self.is_on_curve(Q)):
            raise ValueError("titik tidak ada pada kurva.")
        if P.is_at_infinity():
            return Q
        elif Q.is_at_infinity():
            return P

        if P == Q:
            return self._double_point(P)
        if P == -Q:
            return self.INF

        return self._add_point(P, Q)

    @abstractmethod
    def _add_point(self, P: Point, Q: Point) -> Point:
        pass

    def double_point(self, P: Point) -> Point:
        if not self.is_on_curve(P):
            raise ValueError("titik tidak ada pada kurva.")
        if P.is_at_infinity():
            return self.INF

        return self._double_point(P)

    @abstractmethod
    def _double_point(self, P: Point) -> Point:
        pass

    def mul_point(self, d: int, P: Point) -> Point:
        if not self.is_on_curve(P):
            raise ValueError("titik tidak ada pada kurva.")
        if P.is_at_infinity():
            return self.INF
        if d == 0:
            return self.INF

        res = None
        is_negative_scalar = d < 0
        d = -d if is_negative_scalar else d
        tmp = P
        while d:
            if d & 0x1 == 1:
                if res:
                    res = self.add_point(res, tmp)
                else:
                    res = tmp
            tmp = self.double_point(tmp)
            d >>= 1
        if is_negative_scalar:
            return -res
        else:
            return res

    def neg_point(self, P: Point) -> Point:
        if not self.is_on_curve(P):
            raise ValueError("titik tidak ada pada kurva.")
        if P.is_at_infinity():
            return self.INF

        return self._neg_point(P)

    @abstractmethod
    def _neg_point(self, P: Point) -> Point:
        pass

    @abstractmethod
    def compute_y(self, x: int) -> int:
        pass

    def encode_point(self, plaintext: bytes) -> Point:
        plaintext = len(plaintext).to_bytes(1, byteorder="big") + plaintext
        while True:
            x = int.from_bytes(plaintext, "big")
            y = self.compute_y(x)
            if y:
                return Point(x, y, self)
            plaintext += urandom(1)

    def decode_point(self, M: Point) -> bytes:
        byte_len = int_length_in_byte(M.x)
        plaintext_len = (M.x >> ((byte_len - 1) * 8)) & 0xff
        plaintext = ((M.x >> ((byte_len - plaintext_len - 1) * 8))
                     & (int.from_bytes(b"\xff" * plaintext_len, "big")))
        return plaintext.to_bytes(plaintext_len, byteorder="big")

@dataclass
class ElGamal:
    curve: Curve

    def encrypt(self, plaintext: bytes, public_key: Point,
                randfunc: Callable = None) -> Tuple[Point, Point]:
        return self.encrypt_bytes(plaintext, public_key, randfunc)

    def decrypt(self, private_key: int, C1: Point, C2: Point) -> bytes:
        return self.decrypt_bytes(private_key, C1, C2)

    def encrypt_bytes(self, plaintext: bytes, public_key: Point,
                      randfunc: Callable = None) -> Tuple[Point, Point]:
        # Encode plaintext into a curve point
        M = self.curve.encode_point(plaintext)
        return self.encrypt_point(M, public_key, randfunc)

    def decrypt_bytes(self, private_key: int, C1: Point, C2: Point) -> bytes:
        M = self.decrypt_point(private_key, C1, C2)
        return self.curve.decode_point(M)

    def encrypt_point(self, plaintext: Point, public_key: Point,
                      randfunc: Callable = None) -> Tuple[Point, Point]:
        randfunc = randfunc or urandom
        # Base point G
        G = self.curve.G
        M = plaintext

        random.seed(randfunc(1024))
        k = random.randint(1, self.curve.n)

        C1 = k * G
        C2 = M + k * public_key
        return C1, C2

    def decrypt_point(self, private_key: int, C1: Point, C2: Point) -> Point:
        M = C2 + (self.curve.n - private_key) * C1
        return M

def gen_private_key(curve: Curve,
                    randfunc: Callable = None) -> int:
    order_bits = 0
    order = curve.n

    while order > 0:
        order >>= 1
        order_bits += 1

    order_bytes = (order_bits + 7) // 8
    extra_bits = order_bytes * 8 - order_bits

    rand = int(hexlify(randfunc(order_bytes)), 16)
    rand >>= extra_bits

    while rand >= curve.n:
        rand = int(hexlify(randfunc(order_bytes)), 16)
        rand >>= extra_bits

    return rand

def get_public_key(d: int, curve: Curve) -> Point:
    return d * curve.G

def gen_keypair(curve: Curve,
                randfunc: Callable = None) -> Tuple[int, Point]:
    randfunc = randfunc or urandom
    private_key = gen_private_key(curve, randfunc)
    public_key = get_public_key(private_key, curve)
    return private_key, public_key

class MontgomeryCurve(Curve):
    def _is_on_curve(self, P: Point) -> bool:
        left = self.b * P.y * P.y
        right = (P.x * P.x * P.x) + (self.a * P.x * P.x) + P.x
        return (left - right) % self.p == 0

    def _add_point(self, P: Point, Q: Point) -> Point:
        # s = (yP - yQ) / (xP - xQ)
        # xR = b * s^2 - a - xP - xQ
        # yR = yP + s * (xR - xP)
        delta_x = P.x - Q.x
        delta_y = P.y - Q.y
        s = delta_y * modinv(delta_x, self.p)
        res_x = (self.b * s * s - self.a - P.x - Q.x) % self.p
        res_y = (P.y + s * (res_x - P.x)) % self.p
        return - Point(res_x, res_y, self)

    def _double_point(self, P: Point) -> Point:
        # s = (3 * xP^2 + 2 * a * xP + 1) / (2 * b * yP)
        # xR = b * s^2 - a - 2 * xP
        # yR = yP + s * (xR - xP)
        up = 3 * P.x * P.x + 2 * self.a * P.x + 1
        down = 2 * self.b * P.y
        s = up * modinv(down, self.p)
        res_x = (self.b * s * s - self.a - 2 * P.x) % self.p
        res_y = (P.y + s * (res_x - P.x)) % self.p
        return - Point(res_x, res_y, self)

    def _neg_point(self, P: Point) -> Point:
        return Point(P.x, -P.y % self.p, self)

    def compute_y(self, x: int) -> int:
        right = (x * x * x + self.a * x * x + x) % self.p
        inv_b = modinv(self.b, self.p)
        right = (right * inv_b) % self.p
        y = modsqrt(right, self.p)
        return y

Curve25519 = MontgomeryCurve(
    name="Curve25519",
    a=486662,
    b=1,
    p=0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed,
    n=0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed,
    G_x=0x9,
    G_y=0x20ae19a1b8a086b4e01edd2c7748d14c923d4d7e6d7c61b229e9c5a27eced3d9
)

def genkey():
    # Generate key pair
    pri_key, pub_key = gen_keypair(Curve25519)
    return(str(pri_key), str(pub_key.x), str(pub_key.y))

def encrypt(msg,X,Y):
    pubkey = Point(x=X, y=Y, curve= Curve25519)
    cipher_elg = ElGamal(Curve25519)
    cipher = [None, None]
    cipher[0], cipher[1] = cipher_elg.encrypt(bytes(msg, 'utf-8'), pubkey)
    return(str(cipher[0].x), str(cipher[0].y), str(cipher[1].x), str(cipher[1].y))

def decrypt(X1,Y1,X2,Y2,pri_key):
    C1,C2 = Point(x=X1, y=Y1, curve= Curve25519), Point(x=X2, y=Y2, curve= Curve25519)
    cipher_elg = ElGamal(Curve25519)
    new_plaintext = cipher_elg.decrypt(pri_key, C1, C2)
    return(new_plaintext)


if __name__ == "__main__":
    chip = '47219836151274849084795432780961711889159831815868450919637535588788276887464,3589964298740270068168142807808225062830555588925438701698465844611706310677,10425927736033147098529605131165654794068965651416248823885198509609915894406,13100155410684020220033954875070290732638278643316153941639021503888465240502'
    data = list(map(int, chip.split(',')))
    print(type(decrypt(data[0],data[1],data[2], data[3], 4623587483672153035531486325178052260445142004070364372905315567495204548524)))