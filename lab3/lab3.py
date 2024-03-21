import hashlib
import os
import re
from shutil import disk_usage
from tkinter import *
import tkinter as tk
from tkinter import ttk
import json
from tkinter import messagebox
from ctypes import *
import winreg


import psutil

admin_username = "Admin"

try:
    with open("users.json", "r") as f:
        user_data = json.load(f)
except FileNotFoundError:
    # If the file does not exist, create an empty dictionary
    user_data = {"Admin": {"password": "", "blocked": False}, "setting": [True, True, True]}
    with open('users.json', 'w') as f:
        json.dump(user_data, f)


def login(root):
    root.title('Log In')
    root.geometry('300x300')
    login = tk.StringVar()
    login_label = tk.Label(root, bg='yellow', fg='brown', text=f'Log: ')
    login_label.pack()
    login_label.place(x=20, y=5)
    login = tk.Entry(root, width=25, textvariable=login)
    login.pack()
    login.place(x=60, y=5)

    password = tk.StringVar()
    password_label = tk.Label(root, bg='yellow', fg='brown', text=f'Pass: ')
    password_label.pack()
    password_label.place(x=20, y=25)

    password = tk.Entry(root, width=25, textvariable=password, show="*")
    password.pack()
    password.place(x=60, y=25)

    button = tk.Button(root, text="Login", width=10, bg="yellow", fg="brown",
                       command=lambda: check_user(login.get(), password.get()))
    button.place(x=230, y=4)
    button = tk.Button(root, text="Info", width=10, command=lambda: info())
    button.place(x=230, y=25)


def info():
    messagebox.showinfo("Info", "It was created by FB01 Korabelskyi Taras\nVariant - 2")


misses = 3


def check_user(username, password):
    global misses
    if admin_or_not(username):
        if user_data[username]["password"] == "":
            messagebox.showerror("You need to setup a password!")
            first_login(username)
        elif user_data[username]["password"] == password:
            admin_menu()
        else:
            messagebox.showerror("Wrong password", "Wrong PASSWORD!!!")
            misses -= 1
            print(misses)
            if misses == 0:
                exit()
    else:

        if user_data[username]["password"] == "":
            messagebox.showerror("You need to setup a password!")
            first_login(username)
        elif user_data[username]["password"] == password:
            user_menu(username)
        elif username not in user_data:
            messagebox.showerror("Wrong username", "WRONG USERNAME!!!")
        else:

            messagebox.showerror("Wrong password", "Wrong PASSWORD!!!")
            misses -= 1
            print(misses)
            if misses == 0:
                exit()


def admin_or_not(username):
    return username == admin_username


def first_login(login):
    new_window(root, '250x280')
    root.title('First Login')
    tk.Label(root, bg="grey", fg="brown", text=f'You are signed in as "{login}"').pack()
    tk.Label(root, bg="grey", fg="brown", text='Please, create a password').pack()

    password = tk.StringVar()
    password_label = tk.Label(root, bg="grey", fg="brown", text="Password:")
    password_label.pack(pady=10)
    password_entry = tk.Entry(root, width=25, textvariable=password, show="*")
    password_entry.pack()

    password2 = tk.StringVar()
    password2_label = tk.Label(root, text="Repeat Password:")
    password2_label.pack(pady=10)
    password2_entry = tk.Entry(root, width=25, textvariable=password2, show="*")
    password2_entry.pack()

    button = tk.Button(root, text="Create", width=25,
                       command=lambda: create_password(login, password.get(), password2.get()))
    button.pack(pady=10)

    button = tk.Button(root, text="Exit", width=25, command=lambda: exit())
    button.pack(pady=10)


def pass_change(login):
    new_window(root, '250x300')
    root.title('Change Password')

    old_pass = tk.StringVar()
    tk.Label(root, text='Change Password').pack()
    old_pass_label = tk.Label(root, text="Old Password:")
    old_pass_label.pack(pady=10)
    old_pass_entry = tk.Entry(root, width=25, textvariable=old_pass, show="*")
    old_pass_entry.pack()
    old_pass_entry.focus()

    password = tk.StringVar()
    password_label = tk.Label(root, text="New Password:")
    password_label.pack(pady=10)
    password_entry = tk.Entry(root, width=25, textvariable=password, show="*")
    password_entry.pack()

    password2 = tk.StringVar()
    password2_label = tk.Label(root, text="Confirm New Password:")
    password2_label.pack(pady=10)
    password2_entry = tk.Entry(root, width=25, textvariable=password2, show="*")
    password2_entry.pack()

    button = tk.Button(root, text="Change Password", width=25,
                       command=lambda: change_password(login, old_pass.get(), password.get(), password2.get()))
    button.pack(pady=10)

    button = tk.Button(root, text="Back to Menu", width=25, command=lambda: admin_menu())
    button.pack(pady=10)


def admin_menu():
    new_window(root, '250x300')
    root.title('Admin Menu')
    tk.Label(root, text=f'You are signed in as Admin').pack()

    button = tk.Button(root, text="Change password", width=20, command=lambda: pass_change(admin_username))
    button.pack(pady=10)

    button = tk.Button(root, text="User list", width=20, command=lambda: get_userlist())
    button.pack(pady=10)

    button = tk.Button(root, text="Register an user", width=20, command=lambda: reg_form())
    button.pack(pady=10)

    button = tk.Button(root, text="Ban/Unban a User", width=20, command=lambda: ban_unban())
    button.pack(pady=10)

    button = tk.Button(root, text="Password Settings", width=20, command=lambda: pass_settings())
    button.pack(pady=10)

    button = tk.Button(root, text="Exit", width=20, command=lambda: leave())
    button.pack(pady=10)


def user_menu(login):
    new_window(root, '300x200')
    root.title('User menu')
    tk.Label(root, text=f'You are signed as "{login}"').pack()

    button = tk.Button(root, text='Change password', width=30, command=lambda: pass_change(login)).pack()

    button = tk.Button(root, text='Exit', width=25, command=lambda: exit()).pack()


def change_password(login, old_pass, pass1, pass2):
    if (user_data[login]["password"] == old_pass):
        if pass1 == pass2:

            result = check_password(pass1)

            if result[0] and result[1] and result[2]:
                user_data[login]["password"] = pass1
                with open('users.json', 'w') as fp:
                    json.dump(user_data, fp)
                messagebox.showinfo("Success", f"You have changed password for '{login}'")
                if admin_or_not(login):
                    admin_menu()
                else:
                    user_menu(login)
            else:
                if not result[0]:
                    result[0] = 'Lowercase Letters'
                else:
                    result[0] = ''
                if not result[1]:
                    result[1] = 'Uppercase Letters'
                else:
                    result[1] = ''
                if not result[2]:
                    result[2] = 'Digits'
                else:
                    result[2] = ''
                error = f'Password must contain: {result[0]} {result[1]} {result[2]}'
                messagebox.showerror("Error", error)
        else:
            messagebox.showerror("Error", "Passwords are Different!")
    else:
        messagebox.showerror("Error", "Wrong Old Password")


def get_userlist():
    new_window(root, "400x300")
    root.title('User List')
    tk.Label(root, text=f'User List').pack()

    style = ttk.Style(root)
    style.theme_use("clam")
    style.configure("Treeview", fieldbackground="red", background="black", foreground="blue")
    style.configure("Treeview.Heading", background=[('!active', 'red'), ('active', 'blue')], foreground="black")

    table = ttk.Treeview(root)
    table['columns'] = ('Login', 'Password', 'Blocked')

    table.column("#0", width=0, stretch='no')
    table.heading("#0", text="")

    table.column("Login", anchor='center', width=140)
    table.heading("Login", text="Login", anchor='center')

    table.column("Password", anchor='center', width=140)
    table.heading("Password", text="Password", anchor='center')

    table.column("Blocked", anchor='center', width=140)
    table.heading("Blocked", text="Blocked", anchor='center')
    i = 0
    for login in user_data.keys():
        if login == "setting": continue
        table.insert(parent='', index='end', iid=i, text='',
                     values=(login, user_data[login]["password"], user_data[login]["blocked"]))
        i += 1
    table.pack()

    login_button = tk.Button(root, text="Back to Menu", width=25, command=lambda: admin_menu())
    login_button.pack(pady=10)


def reg_form():
    new_window(root, '250x180')
    root.title('User Registration')
    tk.Label(root, text=f'User registration').pack()

    login = tk.StringVar()
    login_label = tk.Label(root, text="Login:")
    login_label.pack(pady=10)
    login_entry = tk.Entry(root, width=25, textvariable=login)
    login_entry.pack()
    login_entry.focus()

    button = tk.Button(root, text="Register", width=25, command=lambda: register_user(login.get()))
    button.pack(pady=10)

    button = tk.Button(root, text="Back to menu", width=25, command=lambda: admin_menu())
    button.pack(pady=10)


def register_user(login):
    password = ''
    if (login not in user_data):
        user_data[login] = {'password': password, 'blocked': False}
        with open('users.json', 'w') as fp:
            json.dump(user_data, fp)
        messagebox.showinfo("Success", f"'{login}' was added to database")
        print(user_data)
    else:
        messagebox.showerror("Error", "Login already exists")


def create_password(login, password, password2):
    if password == password2:

        result = check_password(password)

        if result[0] and result[1] and result[2]:
            user_data[login]["password"] = password
            with open('users.json', 'w') as fp:
                json.dump(user_data, fp)
            messagebox.showinfo("Success", f"You have created password for '{login}'")
            if admin_or_not(login):
                admin_menu()
            else:
                user_menu(login)
        else:
            if not result[0]:
                result[0] = 'lowercase letters'
            else:
                result[0] = ''
            if not result[1]:
                result[1] = 'Uppercase letters'
            else:
                result[1] = ''
            if not result[2]:
                result[2] = 'Symbols + - / *'
            else:
                result[2] = ''
            error = f'Password must contain: {result[0]} {result[1]} {result[2]}'
            messagebox.showerror("Error", error)
    else:
        messagebox.showerror("Error", "Passwords are different")


def check_password(password):
    result = [True, True, True]

    if user_data['setting'][0]:
        if re.search('[a-z]', password) == None:
            result[0] = False

    if user_data['setting'][1]:
        if re.search('[A-Z]', password) == None:
            result[1] = False

    if user_data['setting'][2]:
        if re.search('[+, -, /, *]', password) == None:
            result[2] = False

    return result


def ban_unban():
    new_window(root, '250x240')
    root.title('Ban/Unban Menu')
    tk.Label(root, text=f'Ban/Unban User').pack()

    login = tk.StringVar()
    login_label = tk.Label(root, text="Login:")
    login_label.pack(pady=10)
    login_entry = tk.Entry(root, width=25, textvariable=login)
    login_entry.pack()
    login_entry.focus()

    button = tk.Button(root, text="Ban", width=25, command=lambda: ban(login, True))
    button.pack(pady=10)

    button = tk.Button(root, text="Unban", width=25, command=lambda: ban(login, False))
    button.pack(pady=10)

    button = tk.Button(root, text="Back to menu", width=25, command=lambda: admin_menu())
    button.pack(pady=10)


def ban(login, type):
    login = login.get()
    if login == admin_username:
        messagebox.showerror("About Admin", "Admin cannot be banned!!!")
    elif (login in user_data.keys()):
        user_data[login]["blocked"] = type
        if type:
            messagebox.showinfo("Success", f"'{login}' was banned")
        else:
            user_data[login]["blocked"] = False

            messagebox.showinfo("Success", f"'{login}' was unbanned")
    else:
        messagebox.showerror("Error", "User not found")
    with open('users.json', 'w') as fp:
        json.dump(user_data, fp)


def pass_settings():
    new_window(root, '250x170')
    root.title('Password Settings')
    tk.Label(root, text=f'Password Settings').pack(pady=(0, 20))

    var1 = tk.BooleanVar()
    var2 = tk.BooleanVar()
    var3 = tk.BooleanVar()

    def change_settings(var, index):
        var = var.get()
        user_data['setting'][index] = var
        with open('users.json', 'w') as fp:
            json.dump(user_data, fp)

    check1 = tk.Checkbutton(root, text='Lowercase letters', variable=var1, onvalue=True, offvalue=False,
                            command=lambda: change_settings(var1, 0))
    check1.pack()

    check2 = tk.Checkbutton(root, text='Uppercase letters', variable=var2, onvalue=True, offvalue=False,
                            command=lambda: change_settings(var2, 1))
    check2.pack()

    check3 = tk.Checkbutton(root, text='Symbols + - / *', variable=var3, onvalue=True, offvalue=False,
                            command=lambda: change_settings(var3, 2))
    check3.pack()

    if user_data['setting'][0]:
        check1.select()
    else:
        check1.deselect()

    if user_data['setting'][1]:
        check2.select()
    else:
        check2.deselect()

    if user_data['setting'][2]:
        check3.select()
    else:
        check3.deselect()

    button = tk.Button(root, text="Back to Menu", width=25, command=lambda: admin_menu())
    button.pack(pady=10)


def leave():
    new_window(root)
    login(root)


def new_window(root, geometry=None):
    for widget in root.winfo_children():
        widget.destroy()
    if geometry is not None:
        root.geometry(geometry)


def keychecker(path='C:'):
    username = os.getlogin()  # користувач
    sysname = os.environ['COMPUTERNAME']  # назва системи
    path_to_windows = os.environ['WINDIR']  # шлях до папки з віндовс
    path_to_windows_system_fiels = os.environ['WINDIR'] + "\\System32\\"
    screen_size = (windll.user32.GetSystemMetrics(0))  # ширина екрану
    mouse = windll.user32.GetSystemMetrics(43)  # кнопки миші
    size_of_disk = disk_usage(os.path.splitdrive(os.getcwd())[0])[0]  # розмір диску для встановлення
    # type_of_disk = disk_usage(os.path.splitdrive(os.getcwd())[:3])[2]
    for disk_drive in psutil.disk_partitions(all=False):
        if os.path.abspath(path)[:3] in disk_drive:
            type_of_disk = disk_drive[2]


    data = [username, sysname, path_to_windows,
            path_to_windows_system_fiels,
            screen_size, mouse, type_of_disk,
            size_of_disk]
    print(data)
    # type_of_disk]
    text = ' '.join([str(elem) for elem in data])
    hash_for_key = hashlib.sha256(text.encode()).hexdigest()
    print(hash_for_key)
    # key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 'SOFTWARE\\Korabelskyi', 0, winreg.KEY_READ)
    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, "SOFTWARE\\Korabelskyi")
    result = winreg.QueryValueEx(key, "Signature")[0]
    winreg.CloseKey(key)


    return result == hash_for_key

def generate_session_key(key):
    # Generate a session key using MD2 hash algorithm
    session_key = MD2.new(key).digest()

    return session_key

def write_user_data(session_key, user_data):
    with open('users.json', 'w') as f:
        json.dump(user_data, f)
    encrypt_file(session_key)

def read_user_data(session_key):
    try:
        decrypt_file(session_key)
        with open("users.json", "r") as f:
            user_data = json.load(f)
        encrypt_file(session_key)
        return user_data
    except FileNotFoundError:
        user_data = {"ADMIN": {"password": "", "blocked": False}, "setting": [True, True, True]}
        with open('users.json', 'w') as f:
            json.dump(user_data, f)
        encrypt_file(session_key)
        return user_data

def write_session_key(key):
    with open("secret", "wb") as f:
        f.write(key)

def read_session_key():
    try:
        with open("secret", "rb") as f:
            session_key = f.read()
            return session_key
    except FileNotFoundError:
        return False
    
def check_session_key(key):
    session_key = read_session_key()
    if session_key == key:
        return key
        # messagebox succesfully
    else:
        pass
        # messagebox error and root.quit()

def encrypt_file(session_key, filename="users.json", output_filename="db"):
    chunksize = 64 * 1024

    # Generate an initialization vector (IV) using MD2 hash algorithm
    iv = MD2.new(session_key).digest()

    # Create the encryption cipher using AES in Ciphertext feedback (CFB) mode
    cipher = AES.new(session_key, AES.MODE_CFB, iv)

    # Open the input and output files, and encrypt the data in chunks
    with open(filename, 'rb') as input_file, open(output_filename, 'wb') as output_file:
        output_file.write(iv)
        while True:
            chunk = input_file.read(chunksize)
            if len(chunk) == 0:
                break
            encrypted_chunk = cipher.encrypt(chunk)
            output_file.write(encrypted_chunk)

    # Remove the original file
    os.remove(filename)

def decrypt_file(session_key, filename="db", output_filename="users.json"):
    chunksize = 64 * 1024

    # Open the input and output files, and decrypt the data in chunks
    with open(filename, 'rb') as input_file, open(output_filename, 'wb') as output_file:
        iv = input_file.read(16)
        cipher = AES.new(session_key, AES.MODE_CFB, iv)
        while True:
            chunk = input_file.read(chunksize)
            if len(chunk) == 0:
                break
            decrypted_chunk = cipher.decrypt(chunk)
            output_file.write(decrypted_chunk)

    # Remove the encrypted file
    os.remove(filename)

def func_check_session_key(key, is_new):
    if key == "":
        messagebox.ERROR("You need to write passphrase!!!")
        first_initializing()
    else:
        if is_new:
            messagebox.INFO('INFO',"New passphrase set up!")
            session_key = generate_session_key(key.encode())
            write_session_key(session_key)
            login(root)
        else:
            if check_session_key(generate_session_key(key.encode())):
                messagebox.INFO("Passphrase is correct!")
                login(root)
            else:
                messagebox.ERROR("Passphrase is wrong!")
                first_initializing()

def first_initializing():
    if read_session_key():
        new_window(root, '250x200')
        root.title('Enter passphrase')

        def handler(e):
            func_check_session_key(secret_phrase_entry.get(), False)

        root.bind('<Return>', handler)

        label = tk.Label(root, text="Passphrase find, enter correct passphrase!")
        secret_phrase_label = tk.Label(root, text="Enter the passphrase:")
        secret_phrase_entry = tk.Entry(root, show="*")
        login_button = tk.Button(root, text="Check passphrase", bg="pink", fg="black",
                                 command=lambda: func_check_session_key(secret_phrase_entry.get(), False))

        label.grid(row=0, column=0, padx=10, pady=20)
        secret_phrase_label.grid(row=1, column=0, padx=10)
        secret_phrase_entry.grid(row=2, column=0, padx=10, pady=20)
        login_button.grid(row=3, columnspan=2, padx=20, sticky="ew")
    else:
        new_window(root, '270x200')
        root.title('Set up new passphrase')

        def handler(e):
            func_check_session_key(secret_phrase_entry.get(), True)

        root.bind('<Return>', handler)

        label = tk.Label(root, text="Passphrase didn't find, enter new passphrase!")
        secret_phrase_label = tk.Label(root, text="Enter the new passphrase:")
        secret_phrase_entry = tk.Entry(root, show="*")
        login_button = tk.Button(root, text="Set up a new passphrase", bg="pink", fg="black",
                                 command=lambda: func_check_session_key(secret_phrase_entry.get(), True))

        label.grid(row=0, column=0, padx=10, pady=20)
        secret_phrase_label.grid(row=1, column=0, padx=10)
        secret_phrase_entry.grid(row=2, column=0, padx=10, pady=20)
        login_button.grid(row=3, columnspan=2, padx=20, pady=20, sticky="ew")

from Crypto.Cipher import AES
from Crypto.Hash import MD2
import os

# Імена вхідного та вихідних файлів
input_file = "plaintext.txt"
temp_file = "temp.txt"
output_file = "decrypted.txt"


key1 = input('Enter the encryption key: ')


def generate_session_key(key):
    # Генерація ключа сеансу за допомогою хеш-алгоритму MD2
    session_key = MD2.new(key.encode()).digest()

    return session_key


def write_session_key(key):
    with open("secret", "wb") as f:
        f.write(key)


def read_session_key():
    try:
        with open("secret", "rb") as f:
            session_key = f.read()
            return session_key
    except FileNotFoundError:
        return False


key = generate_session_key(key1)
if read_session_key() != key:
    print("Wrong Passphrase")
    exit()


# Генерація випадкового вектора ініціалізації
iv = os.urandom(16)

# Створення шифру AES за допомогою кодової фрази та вектора ініціалізації
cipher = AES.new(key, AES.MODE_CBC, iv)

# Open the input and output files and encrypt the data
with open(input_file, "rb") as f_in, open(temp_file, "wb") as f_temp:
    f_temp.write(iv)
    for chunk in iter(lambda: f_in.read(4096), b""):
        if len(chunk) % 16 != 0:
            # Додавання PKCS7, якщо розмір чанку не кратний 16 байтам
            padding_length = 16 - len(chunk) % 16
            chunk += bytes([padding_length] * padding_length)
        encrypted_chunk = cipher.encrypt(chunk)
        f_temp.write(encrypted_chunk)

# Відкриття тимчасового файлу і розшифрування даних
with open(temp_file, "rb") as f_temp, open(output_file, "wb") as f_out:
    iv = f_temp.read(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    for chunk in iter(lambda: f_temp.read(4096), b""):
        decrypted_chunk = cipher.decrypt(chunk)
        if len(chunk) < 4096:
            # Видалення PKCS7,якщо чанк є останнім фрагментом
            padding_length = decrypted_chunk[-1]
            decrypted_chunk = decrypted_chunk[:-padding_length]
        f_out.write(decrypted_chunk)


if __name__ == "__main__":
    root = tk.Tk()
    if keychecker(path='C:'):
        login(root)
        root.mainloop()

    else:
        messagebox.showerror("Error", "Key is wrong!!")
        print("Key is Wrong")
        root.destroy()
