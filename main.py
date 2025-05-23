import random
import math
from math import gcd, sqrt
from sympy import mod_inverse
import argparse

# Словари для кодирования/декодирования
encoding_dict = {
    'А': 10, 'Б': 11, 'В': 12, 'Г': 13, 'Д': 14, 'Е': 15, 'Ё': 16,
    'Ж': 17, 'З': 43, 'И': 18, 'Й': 19, 'К': 20, 'Л': 21, 'М': 22,
    'Н': 23, 'О': 24, 'П': 25, 'Р': 26, 'С': 27, 'Т': 28, 'У': 29,
    'Ф': 30, 'Х': 31, 'Ц': 32, 'Ч': 33, 'Ш': 34, 'Щ': 35, 'Ъ': 36,
    'Ы': 37, 'Ь': 38, 'Э': 39, 'Ю': 40, 'Я': 41, ' ': 42
}

decoding_dict = {str(k): v for v, k in encoding_dict.items()}


class RSA:
    def __init__(self, bit_rate=2):
        self.bit_rate = bit_rate
        self.e = self.m = self.d = 0
        self.p = self.q = 0

    def generate_keys(self):
        """Генерация ключевой пары RSA"""
        self.p = self.q = 0
        while self.p == self.q:
            self.p = self.prime_generation()
            self.q = self.prime_generation()

        self.m = self.p * self.q
        n = (self.p - 1) * (self.q - 1)
        self.e = self.find_e(n)
        self.d = self.find_d(n, self.e)

        while self.e * self.d % n != 1 or self.e == self.d:
            self.e = self.find_e(n)
            self.d = self.find_d(n, self.e)

        return (self.e, self.m), (self.d, self.m)

    def prime_generation(self):
        """Генерация простого числа заданной битности"""
        start_num = 10 ** (self.bit_rate - 1) + 1
        end_num = 10 ** self.bit_rate - 1
        num = random.randint(start_num, end_num)
        while not self.is_prime(num):
            num = random.randint(start_num, end_num)
        return num

    @staticmethod
    def is_prime(n):
        """Проверка числа на простоту"""
        if n % 2 == 0:
            return n == 2
        d = 3
        while d * d <= n and n % d != 0:
            d += 2
        return d * d > n

    @staticmethod
    def find_e(n):
        """Поиск открытой экспоненты"""
        e = random.randint(2, n - 1)
        while gcd(n, e) != 1:
            e = random.randint(2, n - 1)
        return e

    @staticmethod
    def find_d(n, e):
        """Поиск закрытой экспоненты"""
        return mod_inverse(e, n)

    @staticmethod
    def encode(text):
        """Кодирование текста в числовое представление"""
        encoded_text = ''
        for char in text.upper():
            if char in encoding_dict:
                encoded_text += str(encoding_dict[char])
            else:
                print(f"Предупреждение: символ '{char}' не поддерживается и будет пропущен")
        return encoded_text

    def encrypt(self, text, public_key=None):
        """Шифрование текста с использованием открытого ключа"""
        if public_key is None:
            public_key = (self.e, self.m)
        e, m = public_key
        full_text = ''
        enc_text = self.encode(text.strip())

        for i in range(0, len(enc_text), 2):
            code_text = enc_text[i:i + 2]
            if len(code_text) < 2:
                code_text = code_text.ljust(2, '0')
            y = pow(int(code_text), e, m)
            full_text = full_text + str(y) + '-'

        return full_text[:-1]  # Удаляем последний '-'

    def decrypt(self, crypto_text, private_key=None):
        """Расшифрование текста с использованием закрытого ключа"""
        if private_key is None:
            private_key = (self.d, self.m)
        d, m = private_key
        full_text = ''
        nums = str(crypto_text).split('-')

        for num in nums:
            decr_text = pow(int(num), d, m)
            full_text += f"{decr_text:02d}"  # Добавляем ведущий ноль для однозначных чисел

        return self.decode(full_text)

    @staticmethod
    def decode(enc_text):
        """Декодирование числового представления в текст"""
        decoded_text = ''
        for i in range(0, len(enc_text), 2):
            num = enc_text[i: i + 2]
            if num in decoding_dict:
                decoded_text += decoding_dict[num]
            else:
                decoded_text += '?'
        return decoded_text


class RSAAttack:
    """Класс для реализации атак на RSA"""

    @staticmethod
    def factorize(n):
        """Факторизация модуля n (атака на малый модуль)"""
        if n % 2 == 0:
            return 2, n // 2

        # Проверяем нечетные делители до квадратного корня из n
        max_divisor = int(sqrt(n)) + 1
        for i in range(3, max_divisor, 2):
            if n % i == 0:
                return i, n // i

        return None, None

    @staticmethod
    def small_modulus_attack(public_key):
        """Атака на малый модуль RSA"""
        e, n = public_key

        print(f"\nНачата атака на малый модуль n = {n}...")
        p, q = RSAAttack.factorize(n)

        if p is None:
            print("Атака не удалась: не удалось факторизовать модуль n")
            return None

        print(f"Найдены простые делители: p = {p}, q = {q}")

        # Вычисляем функцию Эйлера
        phi = (p - 1) * (q - 1)

        # Находим закрытую экспоненту
        try:
            d = mod_inverse(e, phi)
            print(f"Найден закрытый ключ: d = {d}")
            return (d, n)
        except ValueError:
            print("Не удалось найти закрытую экспоненту")
            return None

    @staticmethod
    def execute_attack(public_key_file='public.key'):
        """Выполнение атаки на основе открытого ключа"""
        try:
            with open(public_key_file, 'r') as f:
                e, n = map(int, f.read().split(','))

            print(f"Загружен открытый ключ: e = {e}, n = {n}")
            private_key = RSAAttack.small_modulus_attack((e, n))

            if private_key:
                print("\nАтака успешна! Найден закрытый ключ.")
                return private_key
            else:
                print("\nАтака не удалась.")
                return None

        except Exception as ex:
            print(f"Ошибка при выполнении атаки: {str(ex)}")
            return None


def save_keys(public_key, private_key, pub_file='public.key', priv_file='private.key'):
    """Сохранение ключей в файлы"""
    with open(pub_file, 'w') as f:
        f.write(f"{public_key[0]},{public_key[1]}")

    with open(priv_file, 'w') as f:
        f.write(f"{private_key[0]},{private_key[1]}")

    print(f"Ключи сохранены в файлы {pub_file} и {priv_file}")


def load_keys(pub_file='public.key', priv_file='private.key'):
    """Загрузка ключей из файлов"""
    try:
        with open(pub_file, 'r') as f:
            e, m = map(int, f.read().split(','))

        with open(priv_file, 'r') as f:
            d, m_priv = map(int, f.read().split(','))

        if m != m_priv:
            raise ValueError("Модули в ключах не совпадают")

        return (e, m), (d, m)

    except Exception as ex:
        print(f"Ошибка загрузки ключей: {str(ex)}")
        return None, None


def read_file(filename):
    """Чтение содержимого файла"""
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            return f.read()
    except Exception as ex:
        print(f"Ошибка чтения файла: {str(ex)}")
        return None


def write_file(filename, content):
    """Запись содержимого в файл"""
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"Результат сохранен в файл: {filename}")
    except Exception as ex:
        print(f"Ошибка записи в файл: {str(ex)}")


def main():
    parser = argparse.ArgumentParser(description='RSA шифрование/дешифрование и атаки')
    parser.add_argument('-g', '--generate', action='store_true', help='Сгенерировать новую пару ключей')
    parser.add_argument('-b', '--bits', type=int, default=2, help='Битность ключей (2-4)')
    parser.add_argument('-e', '--encrypt', action='store_true', help='Зашифровать файл')
    parser.add_argument('-d', '--decrypt', action='store_true', help='Расшифровать файл')
    parser.add_argument('-a', '--attack', action='store_true', help='Выполнить атаку на RSA')
    parser.add_argument('-i', '--input', type=str, help='Входной файл')
    parser.add_argument('-o', '--output', type=str, help='Выходной файл')
    parser.add_argument('--pubkey', type=str, default='public.key', help='Файл открытого ключа')
    parser.add_argument('--privkey', type=str, default='private.key', help='Файл закрытого ключа')

    args = parser.parse_args()

    rsa = RSA(args.bits)

    if args.generate:
        print(f"Генерация ключей {args.bits}-битной длины...")
        public_key, private_key = rsa.generate_keys()
        save_keys(public_key, private_key, args.pubkey, args.privkey)
        print(f"Открытый ключ (e, m): {public_key}")
        print(f"Закрытый ключ (d, m): {private_key}")
        return

    if args.attack:
        print("Запуск атаки на RSA...")
        private_key = RSAAttack.execute_attack(args.pubkey)
        if private_key:
            save_keys((0, 0), private_key, 'fake_public.key', 'hacked_private.key')
        return

    if args.encrypt or args.decrypt:
        if not args.input:
            print("Ошибка: необходимо указать входной файл")
            return

        content = read_file(args.input)
        if content is None:
            return

        public_key, private_key = load_keys(args.pubkey, args.privkey)
        if public_key is None or private_key is None:
            return

        if args.encrypt:
            print("Шифрование...")
            result = rsa.encrypt(content, public_key)
            action = "зашифрован"
        else:
            print("Расшифрование...")
            result = rsa.decrypt(content, private_key)
            action = "расшифрован"

        if args.output:
            write_file(args.output, result)
        else:
            print("\nРезультат:")
            print(result)
            print(f"\nТекст успешно {action}!")
    else:
        print("Не указана операция. Используйте -g, -e, -d или -a")


if __name__ == "__main__":
    main()