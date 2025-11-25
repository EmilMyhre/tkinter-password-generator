import tkinter as tk
from tkinter import messagebox
import secrets
import string

saved_passwords = []

def generate_password():
    try:
        length = int(length_entry.get())
        if length < 8:
            messagebox.showerror("Error", "Password length must be at least 8.")
            return

        letters = string.ascii_letters
        digits = string.digits
        symbols = "!@#$%^&*()-_=+[]{};:,.<>?/"
        all_chars = letters + digits + symbols
        password = ''.join(secrets.choice(all_chars) for _ in range(length))

        result_entry.config(state='normal')
        result_entry.delete(0, tk.END)
        result_entry.insert(0, password)
        result_entry.config(state='readonly')
    except ValueError:
        messagebox.showerror("Error", "Please enter a valid number.")

def save_password():
    pwd = result_entry.get()
    if pwd == "":
        messagebox.showinfo("No Password", "Generate a password first.")
        return
    saved_passwords.append(pwd)
    update_saved_passwords()

def update_saved_passwords():
    saved_list.delete(0, tk.END)
    for p in saved_passwords:
        saved_list.insert(tk.END, p)

window = tk.Tk()
window.title("Secure Password Generator")
window.geometry("650x300")
window.resizable(False, False)

left_frame = tk.Frame(window)
left_frame.pack(side=tk.LEFT, padx=20, pady=10)

title_label = tk.Label(left_frame, text="Password Generator", font=("Arial", 16, "bold"))
title_label.pack(pady=10)

length_frame = tk.Frame(left_frame)
length_frame.pack()

length_label = tk.Label(length_frame, text="Password length:")
length_label.pack(side=tk.LEFT)

length_entry = tk.Entry(length_frame, width=5)
length_entry.insert(0, "16")
length_entry.pack(side=tk.LEFT, padx=5)

generate_button = tk.Button(left_frame, text="Generate Password", command=generate_password)
generate_button.pack(pady=10)

result_entry = tk.Entry(left_frame, font=("Arial", 12), width=30, justify="center", state='readonly')
result_entry.pack(pady=5)

save_button = tk.Button(left_frame, text="Keep Password", command=save_password)
save_button.pack(pady=5)

credit_label = tk.Label(left_frame, text="Made by Emil ☕", font=("Arial", 9), fg="gray")
credit_label.pack(side=tk.BOTTOM, pady=10)

right_frame = tk.Frame(window)
right_frame.pack(side=tk.RIGHT, padx=20, pady=10)

saved_title = tk.Label(right_frame, text="Saved Passwords", font=("Arial", 14, "bold"))
saved_title.pack()

saved_list = tk.Listbox(right_frame, width=30, height=12)
saved_list.pack(pady=10)

window.mainloop()
