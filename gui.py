import customtkinter as ctk
import tkinter as tk
from server import generate_mac as md5_generate_mac, verify as md5_verify
from server_hmac import generate_mac as hmac_generate_mac, verify as hmac_verify
from client import md5_padding, parse_md5_hexdigest, MIN_KEY_LEN, MAX_KEY_LEN, append_data, intercepted_message, intercepted_mac
import pymd5

try:
    from customtkinter import CTkMessageBox
    def show_alert(title, message):
        CTkMessageBox(title=title, message=message)
except ImportError:
    from tkinter import messagebox
    def show_alert(title, message):
        messagebox.showinfo(title, message)

ctk.set_default_color_theme("green")

class MACGui(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("MAC Attack Demo GUI")
        self.geometry("800x600")
        self.resizable(False, False)

        self.title_label = ctk.CTkLabel(self, text="MAC Security Demo", font=("Helvetica", 28, "bold"))
        self.title_label.pack(pady=10)

        # Theme switch
        self.theme_switch = ctk.CTkSwitch(self, text="Dark Mode", command=self.toggle_theme)
        self.theme_switch.pack(pady=5)
        self.theme_switch.select()
        ctk.set_appearance_mode("dark")

        self.tabview = ctk.CTkTabview(self, width=760, height=500)
        self.tabview.pack(padx=10, pady=10)

        self.md5_tab = self.tabview.add("MD5 (Insecure)")
        self.hmac_tab = self.tabview.add("HMAC (Secure)")

        self.build_md5_tab()
        self.build_hmac_tab()

    def toggle_theme(self):
        if self.theme_switch.get() == 1:
            ctk.set_appearance_mode("dark")
        else:
            ctk.set_appearance_mode("light")

    def build_md5_tab(self):
        self.build_common_tab(
            tab=self.md5_tab,
            label_prefix="MD5",
            generate_callback=self.md5_generate_mac,
            verify_callback=self.md5_verify_mac,
            attack_callback=self.md5_attack,
            clear_callback=self.md5_clear
        )

    def build_hmac_tab(self):
        self.build_common_tab(
            tab=self.hmac_tab,
            label_prefix="HMAC",
            generate_callback=self.hmac_generate_mac,
            verify_callback=self.hmac_verify_mac,
            attack_callback=self.hmac_attack,
            clear_callback=self.hmac_clear
        )

    def build_common_tab(self, tab, label_prefix, generate_callback, verify_callback, attack_callback, clear_callback):
        ctk.CTkLabel(tab, text="Message:", font=("Helvetica", 15)).place(x=20, y=20)
        message_entry = ctk.CTkEntry(tab, width=500, font=("Helvetica", 13))
        message_entry.place(x=110, y=20)
        message_entry.insert(0, "hello_world")

        ctk.CTkLabel(tab, text="MAC:", font=("Helvetica", 15)).place(x=20, y=60)
        mac_entry = ctk.CTkEntry(tab, width=500, font=("Helvetica", 13))
        mac_entry.place(x=110, y=60)

        output = ctk.CTkTextbox(tab, width=710, height=250, font=("Consolas", 12))
        output.place(x=20, y=150)

        btn_frame = ctk.CTkFrame(tab, fg_color="transparent")
        btn_frame.place(x=20, y=110)

        ctk.CTkButton(btn_frame, text=f"Generate {label_prefix}", command=generate_callback, width=160).grid(row=0, column=0, padx=10)
        ctk.CTkButton(btn_frame, text=f"Verify {label_prefix}", command=verify_callback, width=160).grid(row=0, column=1, padx=10)
        ctk.CTkButton(btn_frame, text="Run Attack", command=attack_callback, width=160).grid(row=0, column=2, padx=10)
        ctk.CTkButton(btn_frame, text="Clear", command=clear_callback, width=100).grid(row=0, column=3, padx=10)

        if label_prefix == "MD5":
            self.md5_message_entry = message_entry
            self.md5_mac_entry = mac_entry
            self.md5_output = output
        else:
            self.hmac_message_entry = message_entry
            self.hmac_mac_entry = mac_entry
            self.hmac_output = output

    def md5_generate_mac(self):
        msg = self.md5_message_entry.get().encode()
        mac = md5_generate_mac(msg)
        self.md5_mac_entry.delete(0, tk.END)
        self.md5_mac_entry.insert(0, mac)
        self.md5_output.insert(tk.END, f"Generated MAC: {mac}\n")

    def md5_verify_mac(self):
        msg = self.md5_message_entry.get().encode()
        mac = self.md5_mac_entry.get()
        valid = md5_verify(msg, mac)
        self.md5_output.insert(tk.END, f"MAC verification: {'Valid' if valid else 'Invalid'}\n")

    def md5_attack(self):
        import io, sys
        old_stdout = sys.stdout
        sys.stdout = mystdout = io.StringIO()
        try:
            from client import perform_attack
            perform_attack()
        except Exception as e:
            print(f"Attack error: {e}")
        sys.stdout = old_stdout
        output = mystdout.getvalue()
        self.md5_output.insert(tk.END, output + "\n")
        show_alert("Attack Result", "Success!" if "[SUCCESS]" in output else "Failed.")

    def md5_clear(self):
        self.md5_message_entry.delete(0, tk.END)
        self.md5_mac_entry.delete(0, tk.END)
        self.md5_output.delete("1.0", tk.END)

    def hmac_generate_mac(self):
        msg = self.hmac_message_entry.get().encode()
        mac = hmac_generate_mac(msg)
        self.hmac_mac_entry.delete(0, tk.END)
        self.hmac_mac_entry.insert(0, mac)
        self.hmac_output.insert(tk.END, f"Generated HMAC: {mac}\n")

    def hmac_verify_mac(self):
        msg = self.hmac_message_entry.get().encode()
        mac = self.hmac_mac_entry.get()
        valid = hmac_verify(msg, mac)
        self.hmac_output.insert(tk.END, f"HMAC verification: {'Valid' if valid else 'Invalid'}\n")

    def hmac_attack(self):
        output_lines = []
        success = False
        for key_len in range(MIN_KEY_LEN, MAX_KEY_LEN + 1):
            orig_len = key_len + len(intercepted_message)
            padding = md5_padding(orig_len)
            forged_message = intercepted_message + padding + append_data
            state = parse_md5_hexdigest(intercepted_mac)
            total_len = orig_len + len(padding)
            m = pymd5.md5(state=state, count=total_len*8)
            m.update(append_data)
            forged_mac = m.hexdigest()
            output_lines.append(f"Trying key length: {key_len}")
            output_lines.append(f"Forged MAC: {forged_mac}")
            if hmac_verify(forged_message, forged_mac):
                output_lines.append(f"[SUCCESS] Forged MAC valid! Key length: {key_len}")
                success = True
                break
        if not success:
            output_lines.append("Tried all key lengths, none succeeded.")
        self.hmac_output.insert(tk.END, "\n".join(output_lines) + "\n")
        show_alert("Attack Result", "Success!" if success else "Failed. HMAC resisted attack.")

    def hmac_clear(self):
        self.hmac_message_entry.delete(0, tk.END)
        self.hmac_mac_entry.delete(0, tk.END)
        self.hmac_output.delete("1.0", tk.END)

if __name__ == "__main__":
    app = MACGui()
    app.mainloop()
