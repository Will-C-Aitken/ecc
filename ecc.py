import math

# Parameters of secp256k1 where curve is defined by y^2 = x^3 + ax + b (mod p)
# and g is the recommended generator
g_x = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
g_y = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
g = (g_x, g_y)
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
q = 0xFFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8D
a = 0
b = 7


def keygen(g, sk, a, p):
    """
    Generate public key from private key

    Parameters
        g (tuple) generator
        sk (int) secret key
        a (int) part of elliptic curve equation
        p (int) modulus of elliptic curve

    Returns:
        pk (points) public key

    Or

    Raises:
        ValueError if slope denominator is not invertible in any of the addition
        or doubling operations performed during key generation
    """

    try:
        pk = multiply(g, sk, a, p) 
    except ValueError:
        raise

    return(pk)


def encrypt(pk, m, k, g, a, p):
    """
    Encrypt message point to tuple of cipher points. ciphertext 
    y = (kg, m+k(pk))

    Parameters:
        pk (tuple) public key of receiver
        m (tuple) message encoded onto elliptic curve
        k (int) random integer which is an element of the ord(E) (less than q)
        g (tuple) generator
        a (int) part of elliptic curve equation
        p (int) modulus of elliptic curve

    Returns:
        y (tuple of points) ciphertext pair

    Or

    Raises:
        ValueError if slope denominator is not invertible in any of the addition
        or doubling operations performed during encryption
    """

    try:
        y1 = multiply(g, k, a, p)
    except ValueError:
        raise

    try:
        y2 = add(m, multiply(pk, k, a, p), p)
    except ValueError:
        raise

    y = (y1, y2)

    return y


def decrypt(y, sk, a, p):
    """
    Decrypt tuple of cipher points (y1, y2) to original message points on curve.
    decrypted_point = y2 - sk(y1)

    Parameters:
        y (tuple of points) ciphertext which is represented by a tuple of points
        sk (int) secret key
        a (int) part of elliptic curve equation
        p (int) modulus of elliptic curve

    Returns:
        decrypted_point (tuple) original point on curve that will decode to
        character plaintext

    or

    Raises:
        ValueError if slope denominator is not invertible in any of the addition
        or doubling operations performed during decryption
    """

    try:
        sk_y1 = multiply(y[0], sk, a, p)
    except ValueError:
        raise

    neg_sk_y1 = (sk_y1[0], (-sk_y1[1])%p)

    try:
        decrypted_point = add(y[1], neg_sk_y1, p)
    except ValueError:
        raise

    return(decrypted_point)


def encode(char, base, a, b, p):
    """
    Encode characters by mapping integer character code on to ellipitic curve.
    Probabilistic method used is described in "Encoding and Decoding of a Message 
    in the Implementation of Elliptic Curve Cryptography using Kobiltz's Method" 
    by Bh et al. Choose first integer between int(char) and int(char) + base and
    see if it has quadratic residue. If so, return as (x, y) pair, else
    increment by one until residue found. Probability of failed encoding is
    1/2^base. 

    NOTE this encoding method does not uniformly distribute characters onto the
    curve and may have security flaws as a result. Do not use in production

    Parameters:
        char (str) character to be encoded
        base (int) integer predetermined by sender and receiver
        a (int) a used in elliptic curve equation
        b (int) b used in elliptic curve equation
        p (int) elliptic modulus

    Returns:
        point (tuple) encoded character on elliptic curve

    Or

    Raises:
        ValueError: Enoding failed, choose larger base with higher probability
        of succeeding
    """

    char = ord(char)

    i = 0
    while(i < base):
        i = i + 1
        x = base*char + i
        y_inv_2 = ((x**3) + (a*x) + b) % p

        y = modular_sqrt(y_inv_2, p)
        if y == 0:
            continue

        return (x, y)

    raise ValueError("Unable to encode, try again with larger base for " +
                     "better likelihood of finding encoding")


def decode(point, base):
    """
    Decode character from elliptic curve point to text

    Parameters:
        point (tuple) point on elliptic curve
        base (int) same as base used in encoding

    Returns:
        plain (str) character represetnation of point
    """

    plain = chr((point[0] - 1)//base)
    return plain


def add(p1, p2, p):
    """
    Add two points on ellipitic curve described by modulus p

    Parameters:
        p1 (tuple) point 1 in the form (x, y)
        p2 (tuple) point 2 in the form (x, y)
        p (int) modulus of the curve

    Returns:
        p3 (tuple) the result of adding p1 to p2 mod p

    or 

    Raises:
        ValueError if slope denominator is not invertible
    """

    try:
        slope = ((p2[1] - p1[1]) * get_inverse((p2[0] - p1[0]) % p, p)) % p
    except ValueError:
        raise

    x3 = ((slope*slope) - p1[0] - p2[0]) % p
    y3 = (((p1[0] - x3)*slope) - p1[1]) % p

    return (x3, y3)


def double(p1, a, p):
    """
    Double a point, p1 on the elliptic curve described by a and p

    Parameters:
        p1 (tuple) point in the form (x, y)
        a (int) the scalar multiplied by the linear x in the elliptic curve
         equation
        p (int) modulus of the curve

    Returns:
        p2 (tuple) the result of doubling p1 mod p

    or 

    Raises:
        ValueError if slope denominator is not invertible
    """

    try:
        slope = ((3*(p1[0]*p1[0]) + a) * get_inverse((2 * p1[1]) % p, p)) % p
    except ValueError:
        raise

    x2 = ((slope*slope) - (2*p1[0])) % p
    y2 = (((p1[0] - x2)*slope) - p1[1]) % p

    return (x2, y2)


def multiply(p1, alpha, a, p):
    """
    Multiply point, p1 on an ellipitic curvev by a scalar, alpha resulting in 
    a new point on the elliptic curve. Since only doubling and addition between
    points is defined on the curve, scalar multiplication must be performed
    using these operations as its basis. This implementation determines the
    largest powers of 2 the scalar is composed of and calculates the scalar
    multiplied by the powers by repeated doubling. The relevant doubles are
    summed together to yield the new point on the curve.

    Parameters:
        p1 (tuple) point in the form (x, y)
        alpha (int) the scalar value to multiply p1 by
        a (int) from the definition of the curve the operations are performed 
        on p (int) modulus of the curve

    Returns:
        total (tuple) the result of multiplying p1 by alpha

    or 

    Raises:
        ValueError if slope denominator is not invertible in any of the addition
        or doubling operations
    """

    # determine what doubles alpha is composed of
    # alpha = 2^k1 + 2^k2 + ... find list of k's
    doubles = []

    i = int(math.log(alpha, 2))
    r = alpha - 2**i
    doubles.insert(0, i)

    while(r > 1):
        i = int(math.log(r, 2))
        r = r - 2**i
        doubles.insert(0, i)

    j = p1
    
    # add 1 alpha if odd
    total = None
    if r == 1:
        total = p1

    # find and sum all doubles to get new point on curve
    for i in range(1, doubles[-1] + 1):

        try:
            j = double(j, a, p)
        except ValueError:
            raise

        for k in range(0, len(doubles)):
            if(doubles[k] == i):
                if total is None:
                    total = j
                else:
                    try:
                        total = add(total, j, p)
                    except ValueError:
                        raise
                break

    return(total)
    

def get_inverse(x, p):
    """
    Get inverse of x mod p i.e. the integer that when multiplied by x mod p,
    results in 1 mod p

    Parameters:
        x (int) integer to find inverse of
        p (int) modulus

    Returns:
        inv (int) the inverse of x

    or

    Raises:
        ValueError if x and p are not coprime, i.e. their gcd is not 1 and an
        inverse does not exist
    """
    gcd, inv, _ = euclid_ext(x, p)

    if gcd != 1:
        raise ValueError("Inverse does not exist")

    return inv % p
    

def euclid_ext(a, b):
    """
    Extended euclidean algorithm used to solve for gcd, x, and y in the 
    equation gcd(a, b) = ax + yb

    Parameters:
        a (int)
        b (int)

    Returns:
        gcd (int) greatest common divisor of a and b
        x (int) that satisfies described equation
        y (int) that satisfies described equation 
    """

    # Base Case
    if a == 0:
        return b, 0, 1
                    
    gcd, x1, y1 = euclid_ext(b % a, a)
    
    # Update x and y using results of recursive call
    x = y1 - (b//a) * x1
    y = x1
    
    return gcd, x, y


# ----------------------------------------------------------------------------
# The following defines determining if a value has quadratic residue mod p.
# The code is taken from Eli Bendersky's Website and is an implemntation of the
# Tonelli-Shanks Algorithm.
# https://eli.thegreenplace.net/
# ----------------------------------------------------------------------------

def modular_sqrt(a, p):
    """ Find a quadratic residue (mod p) of 'a'. p
        must be an odd prime.

        Solve the congruence of the form:
            x^2 = a (mod p)
        And returns x. Note that p - x is also a root.

        0 is returned is no square root exists for
        these a and p.

        The Tonelli-Shanks algorithm is used (except
        for some simple cases in which the solution
        is known from an identity). This algorithm
        runs in polynomial time (unless the
        generalized Riemann hypothesis is false).
    """
    # Simple cases
    #
    if legendre_symbol(a, p) != 1:
        return 0
    elif a == 0:
        return 0
    elif p == 2:
        return 0
    elif p % 4 == 3:
        return pow(a, (p + 1) // 4, p)

    # Partition p-1 to s * 2^e for an odd s (i.e.
    # reduce all the powers of 2 from p-1)
    #
    s = p - 1
    e = 0
    while s % 2 == 0:
        s //= 2
        e += 1

    # Find some 'n' with a legendre symbol n|p = -1.
    # Shouldn't take long.
    #
    n = 2
    while legendre_symbol(n, p) != -1:
        n += 1

    # Here be dragons!
    # Read the paper "Square roots from 1; 24, 51,
    # 10 to Dan Shanks" by Ezra Brown for more
    # information
    #

    # x is a guess of the square root that gets better
    # with each iteration.
    # b is the "fudge factor" - by how much we're off
    # with the guess. The invariant x^2 = ab (mod p)
    # is maintained throughout the loop.
    # g is used for successive powers of n to update
    # both a and b
    # r is the exponent - decreases with each update
    #
    x = pow(a, (s + 1) // 2, p)
    b = pow(a, s, p)
    g = pow(n, s, p)
    r = e

    while True:
        t = b
        m = 0
        for m in xrange(r):
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
    """ Compute the Legendre symbol a|p using
        Euler's criterion. p is a prime, a is
        relatively prime to p (if p divides
        a, then a|p = 0)

        Returns 1 if a has a square root modulo
        p, -1 otherwise.
    """
    ls = pow(a, (p - 1) // 2, p)
    return -1 if ls == p - 1 else ls
