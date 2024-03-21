import os
import tkinter as tk
from ctypes import *
from tkinter import messagebox
from shutil import disk_usage
import hashlib
import winreg
import shutil
import psutil

import PyInstaller.__main__


def exit(root):  # виход з аккаунту
    clear_window(root)
    start_page(root)


def start_page(root):
    root.configure(background='black', )
    root.title('Setup')
    root.geometry('500x200')

    path = tk.StringVar()
    tk.Label(root, text='Welcome to the setup, please fill the fields').pack()
    login_label = tk.Label(root, text="Path to install:")
    login_label.pack(pady=10)
    login_entry = tk.Entry(root, width=25, textvariable=path)
    login_entry.pack()
    login_entry.focus()
    button = tk.Button(root, text="Install", width=25, command=lambda: install(root, path))
    button.pack(pady=10)


def clear_window(root):  # очищення вікна від елементів
    for widget in root.winfo_children():
        widget.destroy()


def get_info(path=''):  # збір інформації
    username = os.getlogin()  # користувач
    sysname = os.environ['COMPUTERNAME']  # назва системи
    path_to_win = os.environ['WINDIR']  # шлях до папки з віндовс
    path_to_winsys_files = os.environ['WINDIR'] + "\\System32\\"
    screen_size = (windll.user32.GetSystemMetrics(0))  # розмір екрану
    mouse = windll.user32.GetSystemMetrics(43)  # кнопки миші
    size_of_disks = disk_usage(os.path.splitdrive(path)[0])[0]  # розмір диску для встановлення
    
    for disk_drive in psutil.disk_partitions(all=False):
        if os.path.abspath(path)[:3] in disk_drive:
            type_of_disk = disk_drive[2]

    
    return [username, sysname, path_to_win,
            path_to_winsys_files, screen_size, mouse,
            type_of_disk,
            size_of_disks]


def make_hash(data):
    text = ' '.join([str(elem) for elem in data])
    hash_for_key = hashlib.sha256(text.encode()).hexdigest()
    return hash_for_key


def make_key(hash):
    key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, "Software\\Korabelskyi")
    winreg.SetValueEx(key, "Signature", 0, winreg.REG_SZ, hash)
    winreg.CloseKey(key)


def install(root, path, filename='lab1.py'):
    # створення ключа
    path = path.get()
    print(path)
    data = get_info(path)
    print(data)
    hash = make_hash(data)
    print(hash)
    make_key(hash)

    messagebox.showinfo("Great", f"Installing in '{path}'")
    PyInstaller.__main__.run([
        filename,
        '--onefile',
        '--windowed'])
    messagebox.showinfo("Success", f"Instalation Completed!")

    root.destroy()
    # переміщення виконувального файлу в потрібну папку
    shutil.move(f'./dist/{filename[:-3]}.exe', f'{path}\\{filename[:-3]}.exe')
    # видалення зайвого
    os.remove(f'{filename[:-3]}.spec')
    os.chmod('./dist', 0o777)
    shutil.rmtree('./dist')
    os.chmod('./__pycache__', 0o777)
    shutil.rmtree('./__pycache__')
    os.chmod('./build', 0o777)
    os.chmod(f'./build/{filename[:-3]}', 0o777)
    shutil.rmtree('./build')


root = tk.Tk()
start_page(root)

root.mainloop()
