from tkinter import *
from tkinter import ttk
import random
import math


# Функция генерации ключей
def key_generation():
    global e, m, d
    # Устанавливаем битность
    bit_rate = spinbox_var.get()
    # Вызываем функцию генерации простого числа с нужной битностью
    p = q = 0
    while p == q:
        p = prime_generation(bit_rate)
        q = prime_generation(bit_rate)
    print(p, q)
    m = p * q  # Модуль RSA
    n = (p - 1) * (q - 1)
    print(n)
    e = find_e(n)
    d = find_d(n, e)
    while e * d % n != 1 or e == d:
        e = find_e(n)
        d = find_d(n, e)
    # print(d)
    print("Open Key: " + '{' + str(e) + ',' + str(m) + '}')
    print("Private Key: " + '{' + str(d) + ',' + str(m) + '}')
    open_key_text = "Открытый ключ: {" + str(e) + ', ' + str(m) + '}'
    private_key_text = "Закрытый ключ: {" + str(d) + ', ' + str(m) + '}'
    open_key_label['text'] = open_key_text
    private_key_label['text'] = private_key_text
    open_key_label.place(x=20, y=70)
    private_key_label.place(x=20, y=90)
    return m, d, e


def find_d(n, e):
    x, y, a = evklid(n, e)
    if x < y:
        num = x
    else:
        num = y
    d = n - abs(num)
    return d


def evklid(a, b):
    x, xx, y, yy = 1, 0, 0, 1
    while b:
        q = a // b
        a, b = b, a % b
        x, xx = xx, x - xx * q
        y, yy = yy, y - yy * q
    return x, y, a


# Функция генерации простых чисел в соответствии с битностью с помощью перебора всех чисел нужной битности
def prime_generation(bit_rate):
    # Устанавливаем минимальное число нужной битности, откуда начнем поиск простого числа
    start_num = 10 ** (bit_rate - 1) + 1
    end_num = 10 ** bit_rate - 1
    num = random.randint(start_num, end_num)
    while not is_prime(num):
        num = random.randint(start_num, end_num)
    return num


# Функций проверки числа на простоту
def is_prime(n):
    if n % 2 == 0:
        return n == 2
    d = 3
    while d * d <= n and n % d != 0:
        d += 2
    return d * d > n


# Функция выбора открытой экспоненты
def find_e(n):
    e = random.randint(2, n - 1)
    while math.gcd(n, e) != 1:
        e = random.randint(2, n - 1)
    return e


def encode(text):
    encoded_text = ''
    for i in range(len(text)):
        encoded_text = encoded_text + str(encoding_dict[text[i]])
    return encoded_text


def encryption(enc_text):
    global e, m
    full_text = ''
    for i in range(0, len(enc_text), 2):
        code_text = enc_text[i:i + 2]
        y = pow(int(code_text), e) % m
        if i != len(enc_text) - 2:
            full_text = full_text + str(y) + '-'
        else:
            full_text = full_text + str(y)
    encrypted_result.place(x=20, y=175, width=200, height=100)
    encrypted_result['state'] = 'normal'
    encrypted_result.delete(1.0, END)
    encrypted_result.insert(1.0, full_text)
    encrypted_result['state'] = 'disabled'
    return full_text


def decryption(crypto_text):
    global d, m
    full_text = ''
    nums = str(crypto_text).split('-')
    for i in range(len(nums)):
        decr_text = pow(int(nums[i]), d) % m
        full_text = full_text + str(decr_text)
    decoding(full_text)
    encrypted_text.delete(1.0, END)
    return full_text


def decoding(enc_text):
    decoded_text = ''
    for i in range(0, len(enc_text), 2):
        num = enc_text[i: i + 2]
        decoded_text = decoded_text + str(decoding_dict[num])
    result_text['state'] = 'normal'
    result_text.delete(1.0, END)
    result_text.insert(1.0, decoded_text)
    result_text['state'] = 'disabled'
    return decoded_text


def set_keys():
    global e, m, d
    try:
        e = int(open_key_entry_e.get())
        m = int(open_key_entry_m.get())
        d = int(private_key_entry_d.get())
        if int(private_key_entry_m.get()) != m:
            raise ValueError("Модули в ключах не совпадают")

        open_key_text = "Открытый ключ: {" + str(e) + ', ' + str(m) + '}'
        private_key_text = "Закрытый ключ: {" + str(d) + ', ' + str(m) + '}'
        open_key_label['text'] = open_key_text
        private_key_label['text'] = private_key_text
        open_key_label.place(x=20, y=70)
        private_key_label.place(x=20, y=90)
    except ValueError as e:
        error_window = Toplevel(root)
        error_window.title("Ошибка")
        error_label = ttk.Label(error_window, text=f"Ошибка ввода ключей: {str(e)}")
        error_label.pack(padx=10, pady=10)
        ttk.Button(error_window, text="OK", command=error_window.destroy).pack(pady=5)


encoding_dict = {'А': 10, 'Б': 11, 'В': 12, 'Г': 13, 'Д': 14, 'Е': 15, 'Ё': 16, 'Ж': 17, 'И': 18, 'Й': 19, 'К': 20,
                 'Л': 21, 'М': 22, 'Н': 23, 'О': 24, 'П': 25, 'Р': 26, 'С': 27, 'Т': 28, 'У': 29, 'Ф': 30, 'Х': 31,
                 'Ц': 32, 'Ч': 33, 'Ш': 34, 'Щ': 35, 'Ъ': 36, 'Ы': 37, 'Ь': 38, 'Э': 39, 'Ю': 40, 'Я': 41, ' ': 42,
                 'З': 43}
decoding_dict = {'10': 'А', '11': 'Б', '12': 'В', '13': 'Г', '14': 'Д', '15': 'Е', '16': 'Ё', '17': 'Ж', '18': 'И',
                 '19': 'Й', '20': 'К', '21': 'Л', '22': 'М', '23': 'Н', '24': 'О', '25': 'П', '26': 'Р', '27': 'С',
                 '28': 'Т', '29': 'У', '30': 'Ф', '31': 'Х', '32': 'Ц', '33': 'Ч', '34': 'Ш', '35': 'Щ', '36': 'Ъ',
                 '37': 'Ы', '38': 'Ь', '39': 'Э', '40': 'Ю', '41': 'Я', '42': ' ', '43': 'З'}
root = Tk()
root.option_add("*tearOff", FALSE)
root.title("RSA")
root.geometry("500x400")

frame_encryption = ttk.Frame(borderwidth=1, relief=SOLID)
frame_decryption = ttk.Frame(borderwidth=1, relief=SOLID)

open_key_label = ttk.Label(frame_encryption)
private_key_label = ttk.Label(frame_encryption)

frame_encryption.place(x=5, y=5, width=245, height=390)
frame_decryption.place(x=250, y=5, width=245, height=390)

ttk.Label(text="RSA").pack()
ttk.Label(frame_encryption, text="Шифрование").pack()
ttk.Label(frame_decryption, text="Расшифрование").pack()

spinbox_var = IntVar(value=2)
spinbox = ttk.Spinbox(frame_encryption, from_=2, to=4, textvariable=spinbox_var)
spinbox.pack()

ttk.Button(frame_encryption, text="Сгенерировать пару ключей", command=key_generation).pack()

# Поля для ввода ключей вручную
ttk.Label(frame_encryption, text="Ввод ключей вручную:").place(x=20, y=120)

ttk.Label(frame_encryption, text="Открытый ключ (e):").place(x=20, y=150)
open_key_entry_e = ttk.Entry(frame_encryption, width=10)
open_key_entry_e.place(x=130, y=150)

ttk.Label(frame_encryption, text="Модуль (m):").place(x=20, y=170)
open_key_entry_m = ttk.Entry(frame_encryption, width=10)
open_key_entry_m.place(x=130, y=170)

ttk.Label(frame_encryption, text="Закрытый ключ (d):").place(x=20, y=190)
private_key_entry_d = ttk.Entry(frame_encryption, width=10)
private_key_entry_d.place(x=130, y=190)

ttk.Label(frame_encryption, text="Модуль (m):").place(x=20, y=210)
private_key_entry_m = ttk.Entry(frame_encryption, width=10)
private_key_entry_m.place(x=130, y=210)

ttk.Button(frame_encryption, text="Установить ключи", command=set_keys).place(x=70, y=240)

text_to_encrypt = StringVar()
ttk.Entry(frame_encryption, textvariable=text_to_encrypt).place(x=20, y=280)
ttk.Button(frame_encryption, text="Зашифровать",
           command=lambda: encryption(encode(text_to_encrypt.get().upper()))).place(x=150, y=280)
encrypted_label = ttk.Label(frame_encryption, text="Результат шифрования:")
encrypted_label.place(x=20, y=310)
encrypted_result = Text(frame_encryption, wrap="word")
root.clipboard_clear()
ttk.Button(frame_encryption, text="Скопировать",
           command=lambda: encrypted_text.insert(1.0, (encrypted_result.get(1.0, END)))).place(x=150, y=360)
root.resizable(width=False, height=False)

encrypted_text = Text(frame_decryption, wrap="word")
encrypted_text.place(x=10, y=20, width=220, height=80)
ttk.Button(frame_decryption, text="Расшифровать", command=lambda: decryption(encrypted_text.get(1.0, END))).place(x=80,
                                                                                                                  y=110)
result_text = Text(frame_decryption, wrap="word", state=DISABLED)
result_text.place(x=10, y=140, width=220, height=80)
root.mainloop()

m = d = e = 0