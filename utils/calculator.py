
# ---------------------------- Calculator ------------------------------- #

class Calculator:
    """
    This class implements various mathematical operations.
    """

    # Constructor
    def __init__(self):
        pass

    # Methods

    @staticmethod
    def montgomery_ladder(base: int, exponent: int, modulo: int) -> int:
        """
        Perform the Montgomery Ladder algorithm for fast exponentiation.
        :param int base: The base number for the calculation.
        :param int exponent: The exponent for the calculation.
        :param int modulo: The modulo for the calculation.
        :return: The result of the Montgomery Ladder calculation.
        """

        x = 1
        y = base % modulo
        exponent_in_bit = bin(exponent)[2:]

        for bit in exponent_in_bit:
            if bit == "1":
                x = (x * y) % modulo
                y = (y ** 2) % modulo
            else:
                y = (x * y) % modulo
                x = (x ** 2) % modulo

        return x

    @staticmethod
    def __get_invert(num: int, mod: int) -> int:
        """
        Calculates the modular multiplicative inverse of a number.
        :param num: The number to find the inverse of.
        :param mod: The modulo.
        :return: The modular multiplicative inverse of 'num' modulo 'mod'. If the inverse does not exist, the function returns -1.
        """

        m = mod
        x = 0
        y = 1
        x_prev, y_prev = 1, 0

        while m != 0:
            quotient = num // m
            num, m = m, num % m
            x, x_prev = x_prev - quotient * x, x
            y, y_prev = y_prev - quotient * y, y

        return x_prev % mod
