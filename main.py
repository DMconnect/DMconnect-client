import socket
import threading
import tkinter as tk
from tkinter import scrolledtext
from tkinter import Menu, ttk
import os
import sys
import re
import webbrowser
import time
import struct
import hashlib
import hmac
import random
import pyaes
import binascii

class DMC:
    def __init__(self, root, host='dmconnect.hoho.ws', port=42439):
        self.root = root
        self.root.title("DMconnect")
        self.root.geometry("600x255")
        self.host = host
        self.port = port
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.logged_in = False
        self.notifications_enabled = False
        self.logged_in_user = ""
        self.socket_timeout = 30 
        self.waiting_ping_response = False
        self.last_ping_time = 0

        self.encryption_enabled = (int(port) == 42440)
        self.session_key_enc = None
        self.session_key_mac = None
        self._recv_buffer = b""

        style = ttk.Style()
        style.configure("TButton", padding=6)
        style.configure("TLabel", padding=5)

        self.chat_display = scrolledtext.ScrolledText(root, state='disabled', wrap='word', font=("Arial", 11))
        self.chat_display.place(x=10, y=10, width=585, height=100)

        self.chat_display.tag_bind("link", "<Button-1>", self.open_link)
        self.chat_display.tag_bind("link", "<Enter>", self.on_hover)
        self.chat_display.tag_bind("link", "<Leave>", self.on_leave)

        self.enter_message = tk.Label(self.root, text="Enter message:", font=("Arial", 10))
        self.enter_message.place(x=10, y=120)

        self.char_count_label_ = tk.Label(root, text="Chars:", font=("Arial", 10))
        self.char_count_label_.place(x=120, y=120)

        self.char_count_label = tk.Label(root, text=" 0/1000 ", font=("Arial", 10), relief=tk.SUNKEN, borderwidth=2, width=8)
        self.char_count_label.place(x=170, y=120)

        self.nick_label_ = tk.Label(root, text="Nick:", font=("Arial", 10))
        self.nick_label_.place(x=250, y=120)

        self.nick_label = tk.Label(root, text=" ??? ", font=("Arial", 10), relief=tk.SUNKEN, borderwidth=2, width=8)
        self.nick_label.place(x=290, y=120)

        self.notifications = tk.BooleanVar(value=False)

        self.notifications_checkbox = tk.Checkbutton(
            root, text="Auto Pop-up", variable=self.notifications, command=self.toggle_notifications
        )

        self.notifications_checkbox.place(x=410, y=120)

        pixel = tk.PhotoImage(width=1, height=1)
        self.help_button = button = tk.Button(root, text="Help", width=40, height=20,
                       compound="center", padx=0, pady=0, command=self.open_help_window)
        self.help_button.update_idletasks()  
        width = self.help_button.winfo_reqwidth()
        height = self.help_button.winfo_reqheight()

        self.help_button.place(x=550, y=120, width=40, height=20)

        self.help_button2 = button = tk.Button(root, text="About", width=40, height=20,
                       compound="center", padx=0, pady=0, command=self.open_about_window)
        self.help_button2.update_idletasks()  
        width = self.help_button2.winfo_reqwidth()
        height = self.help_button2.winfo_reqheight()

        self.help_button2.place(x=505, y=120, width=40, height=20)

        self.input_frame = tk.Frame(root)
        self.input_frame.grid(row=1, column=0, padx=10, pady=5, sticky="ew")

        self.input_text = tk.Text(root, height=4, wrap='word', font=("Arial", 12))
        self.input_text.place(x=10, y=145, width=580, height=70)  

        self.input_text.tag_config('link', foreground="blue", underline=True)

        self.input_text.bind("<KeyRelease>", self.highlight_links, add="+")
        self.input_text.bind("<KeyRelease>", self.update_char_count, add="+")
        self.input_text.bind("<KeyPress>", self.update_char_count, add="+")
        self.input_text.bind("<Return>", self.handle_return_key)
        self.input_text.bind("<Shift-Return>", self.handle_shift_return_key)

        self.quit_button = tk.Button(root, text="Quit", width=80, height=30,
                        compound="center", padx=0, pady=0, 
                        command=sys.exit)
        self.quit_button.place(x=10, y=220, width=50, height=30)  

        self.members_button = tk.Button(root, text="Members", width=80, height=30,
                        compound="center", padx=0, pady=0, 
                        command=self.request_members)
        self.members_button.place(x=65, y=220, width=65, height=30)  

        self.settings_button = tk.Button(root, text="Send",
                        compound="center", padx=0, pady=0, 
                        command=self.send_message)
        self.settings_button.place(x=505, y=220, width=85, height=30)  
            
        self.context_menu = Menu(root, tearoff=0, font=("Times New Roman", 10))
        self.context_menu.add_command(label="Copy", command=self.copy_message)
        self.context_menu.add_command(label="Paste", command=self.paste_message)
        self.context_menu.add_command(label="Quote", command=self.quote_message)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Quit", command=sys.exit)

        self.context_menu2 = Menu(root, tearoff=0, font=("Times New Roman", 10))
        self.context_menu2.add_command(label="Copy", command=self.copy_message)
        self.context_menu2.add_command(label="Paste", command=self.paste_message)
        self.context_menu2.add_separator()
        self.context_menu2.add_command(label="Quit", command=sys.exit)

        self.chat_display.bind("<Button-3>", self.show_context_menu)
        self.input_text.bind("<Button-3>", self.show_context_menu2)

        root.grid_rowconfigure(0, weight=1)
        root.grid_rowconfigure(1, weight=0)
        root.grid_columnconfigure(0, weight=1)

        self.max_chars = 1000
        self.stop_event = threading.Event()
        self.max_reconnect_attempts = 5
        self.reconnect_delay = 5
        self.reconnect_attempts = 0
        self.last_credentials = None
        self.last_server = None

        self.start_connection()
        self.start_ping_thread()

    def highlight_links(self, event):
        text = self.input_text.get("1.0", tk.END)
        self.input_text.tag_remove("link", "1.0", tk.END)

        for match in re.finditer(r"https?://\S+", text):
            start, end = match.start(), match.end()
            line, char = self.input_text.index("1.0").split(".")
            self.input_text.tag_add("link", str(line) + "." + str(start), str(line) + "." + str(end))

    def toggle_notifications(self):
        self.notifications_enabled = self.notifications.get()

    def open_about_window(self):
        about_window = tk.Toplevel(self.root)
        about_window.title("About DMconnect")
        about_window.geometry("300x190")
        about_window.resizable(False, False)

        tk.Label(about_window, text="DMconnect v0.3", justify="left", font=("Arial", 14, "bold")).pack(pady=10)

        tk.Label(
            about_window,
            text="DMconnect - protocol and program for exchanging\ninstant messages over the Internet. This client \n(chat-program) uses protocol version v3 #4 and \nmade by BitByByte.",
            font=("Arial", 10),
            justify="left",
        ).pack(pady=5)

        tk.Label(
            about_window,
            text="Build Date: 05.09.2025.                                      ",
            font=("Arial", 10, "italic"),
            justify="left",
        ).pack(pady=5)

        tk.Button(about_window, text="OK",
                        compound="center", padx=0, pady=0, 
                        command=about_window.destroy).place(x=230, y=160, width=65, height=25)

        about_window.transient(self.root)
        about_window.grab_set()
        self.root.wait_window(about_window)

    def open_help_window(self):
        about_window = tk.Toplevel(self.root)
        about_window.title("DMconnect help")
        about_window.geometry("300x230")
        about_window.resizable(False, False)

        tk.Label(about_window, text="DMconnect v0.3", justify="left", font=("Arial", 14, "bold")).pack(pady=10)

        help_text = tk.Text(
            about_window,
            font=("Arial", 10),
            wrap="word",
            height=8,
            width=55,
            padx=10,
            pady=10,
            bd=0,
            bg=about_window.cget("bg"),
            fg="black",
            state="normal"
        )

        help_text.pack()

        help_content = "/login <username> <password> - Login with username and password.\n\n" \
                       "/register <username> <password> - Register a new user.\n\n/create_server <server name> - Create a new communication server.\n\n" \
                       "/join_server <server name> - Log in to the communication server.\n\n/list_servers - Get a list of all available servers for communication.\n\n/members - Get list of users on server.\n\n" \
                       "/pm <username> <message> - Send a private message to the specified user.\n\n/act <action> - Chat action, set your status.\n\n/help - Shows this message."

        help_text.insert(tk.END, help_content)
        help_text.tag_configure("bold_command", font=("Arial", 10, "bold"))

        for command in ["/login", "/register", "/create_server", "/join_server", "/list_servers", "/members", "/pm", "/act", "/help"]:
            start_idx = help_text.search(command, "1.0", stopindex=tk.END)
            if start_idx:
                end_idx = str(start_idx) + "+" + str(len(command)) + "c"
                help_text.tag_add("bold_command", start_idx, end_idx)

        help_text.config(state="disabled")

        tk.Button(about_window, text="OK", compound="center", padx=0, pady=0, command=about_window.destroy).place(x=230, y=200, width=65, height=25)

        about_window.transient(self.root)
        about_window.grab_set()
        self.root.wait_window(about_window)


    def start_connection(self):
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.settimeout(self.socket_timeout)  
            self.client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1) 
            self.client_socket.connect((self.host, self.port))
            if self.encryption_enabled:
                self._perform_dh_handshake()
            self.reconnect_attempts = 0
            self.start_receiving_thread()
            
            if self.last_credentials:
                self.restore_session()
                
        except Exception as e:
            self.handle_connection_error(e)

    def handle_connection_error(self, error):
        if self.reconnect_attempts < self.max_reconnect_attempts:
            self.reconnect_attempts += 1
            self.root.after(self.reconnect_delay * 1000, self.start_connection)
        else:
            self.add_message("Error: Connection lost.")
            self.reconnect_attempts = 0 

    def add_message(self, message):
        self.chat_display.config(state='normal')

        start_index = self.chat_display.index(tk.END + "-1c")

        if ":" in message:
            nickname, msg_content = message.split(":", 1)

            if not nickname == "http" and not nickname == "https":
                self.chat_display.insert(tk.END, nickname + ":", 'nickname')
                self.chat_display.insert(tk.END, msg_content + "\n")

                if self.notifications_enabled:
                    self.root.attributes('-topmost', True)
                    self.root.attributes('-topmost', False)
            else:
                self.chat_display.insert(tk.END, message + '\n')
        else:
            self.chat_display.insert(tk.END, message + '\n')

        end_index = self.chat_display.index(tk.END)

        line_number = start_index.split(".")[0] 
        for match in re.finditer(r"https?://\S+", message):
            start, end = match.start(), match.end()
            self.chat_display.tag_add("link", str(line_number) + "." + str(start), str(line_number) + "." + str(end))

        self.chat_display.yview(tk.END)
        self.chat_display.config(state='disabled')
        self.chat_display.tag_config('nickname', font=("Arial", 11, "italic"), foreground='black')
        self.chat_display.tag_config("link", foreground="blue", underline=True)
        self.chat_display.tag_bind("link", "<Button-1>", self.open_link)

    def open_link(self, event):
        index = self.chat_display.index(tk.CURRENT)
        link_range = self.chat_display.tag_prevrange("link", index)

        if not link_range:
            link_range = self.chat_display.tag_nextrange("link", index)

        if link_range:
            start, end = link_range
            link = self.chat_display.get(start, end)
            webbrowser.open(link) 

    def on_hover(self, event):
        self.chat_display.config(cursor="hand2")

    def on_leave(self, event):
        self.chat_display.config(cursor="")

    def send_message(self):
        message = self.input_text.get("1.0", tk.END).strip()
        if len(message) <= self.max_chars and message.strip():
            try:
                self.send_normal_message(message)
                self.handle_commands(message)
            except (socket.error, ConnectionError):
                self.handle_connection_error("Error sending message")
                return
        else:
            self.add_message("Error: The message must contain no more than " + str(self.max_chars) + " chars.")
        self.input_text.delete("1.0", tk.END)
        self.char_count_label.config(text=" 0/1000 ")

    def handle_commands(self, message):
        if message.startswith('/login '):
            self.process_login(message)
        elif message.startswith('/register '):
            self.process_registration(message)
        elif message.startswith('/join_server '):
            self.process_join_server(message)

    def send_normal_message(self, message):
        if self.logged_in or message.startswith('/login ') or message.startswith('/register '):
            try:
                if self.encryption_enabled:
                    self._enc_send(message)
                else:
                    self.client_socket.send(message.encode('utf-8'))
                if message.lower() == 'exit':
                    self.stop_event.set()
                    self.client_socket.close()
                    self.root.quit()
            except Exception as e:
                self.add_message("Error sending message: " + str(e))
                self.handle_connection_error(e)
        else:
            self.add_message("Error: Login failed. Use /login <username> <password> to log in.")

    def process_login(self, message):
        parts = message[len('/login '):].split()
        if len(parts) == 2:
            username, password = parts
            string_result = "/login " + str(username) + " " + str(password)
            self.nick_label.configure(text=" " + str(username) + " ")
            self.logged_in_user = username
            self.last_credentials = (username, password)
        else:
            self.add_message("Error: Please provide a username and password after the /login command.")

    def process_registration(self, message):
        parts = message[len('/register '):].split()
        if len(parts) == 2:
            username, password = parts
            string_result = "/register " + str(username) + " " + str(password)
        else:
            self.add_message("Error: Please provide a username and password after the /register command.")

    def process_join_server(self, message):
        server_name = message[len('/join_server '):].strip()
        if server_name:
            string_to_send = "/join_server " + server_name
            self.last_server = server_name
        else:
            self.add_message("Error: Please specify a server name after the /join_server command.")

    def request_members(self):
        if self.logged_in:
            if self.encryption_enabled:
                self._enc_send("/members")
            else:
                self.client_socket.send("/members".encode('utf-8'))
        else:
            self.add_message("Error: Not logged in. Please log in.")

    def handle_return_key(self, event):
        if not event.state & 0x0001:
            self.send_message()
        return "break"

    def handle_shift_return_key(self, event):
        self.input_text.insert(tk.END, '\n')
        return "break"

    def update_char_count(self, event=None):
        current_length = len(self.input_text.get("1.0", tk.END)) - 1
        self.char_count_label.config(text=" " + str(current_length) + "/" + str(self.max_chars) + " ")

    def receive_messages(self):
        while not self.stop_event.is_set():
            try:
                if self.encryption_enabled:
                    message = self._enc_recv()
                    if message is None:
                        continue
                    message = message.strip()
                else:
                    message = self.client_socket.recv(1024).decode('utf-8').strip()
                    if not message:
                        raise ConnectionError("Connection lost")
                if message:
                    self.process_received_message(message)
            except socket.timeout:
                continue
            except (socket.error, ConnectionError) as e:
                if not self.stop_event.is_set():
                    self.handle_connection_error(e)
                break

    def process_received_message(self, message):
        message = message.replace("*Ping!*", "")
        if not message:
            return

        if self.waiting_ping_response and message == "*Ping!*":
            self.waiting_ping_response = False
            return 

        if message.count("Enter command (/login /register):") > 1:
            message = "Enter command (/login /register):"

        if message.startswith("Login successful."):
            self.logged_in = True
            self.add_message("Login successful!")
            if getattr(self, 'logged_in_user', ""):
                self.root.title("DMconnect [" + str(self.logged_in_user) + "]")
        elif message.startswith("Invalid username or password."):
            self.add_message("Login error: Invalid credentials.")
            self.nick_label.configure(text=" ??? ")
        elif message.startswith("This username is already in use."):
            self.add_message("Login error: username is already in use.")
            self.nick_label.configure(text=" ??? ")
        elif message.startswith("Registration successful. Please log in."):
            self.add_message("Registration successful! Please log in.")
        elif message.startswith("Username already taken. Try another."):
            self.add_message("Username is already taken. Try another one.")
        elif message.startswith("Available servers:"):
            self.add_message(message)
        elif message.startswith("Joined server '"):
            self.add_message(message)
        elif message.startswith("Server does not exist."):
            self.add_message("Error: server not found.")
        else:
            self.add_message(message)
        self.waiting_ping_response = False

    def start_receiving_thread(self):
        receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
        receive_thread.start()

    def show_context_menu(self, event):
        try:
            self.context_menu.post(event.x_root, event.y_root)
        except tk.TclError:
            pass

    def show_context_menu2(self, event):
        try:
            self.context_menu2.post(event.x_root, event.y_root)
        except tk.TclError:
            pass

    def copy_message(self):
        try:
            selected_text = self.chat_display.get(tk.SEL_FIRST, tk.SEL_LAST)
            self.root.clipboard_clear()
            self.root.clipboard_append(selected_text)
        except tk.TclError:
            pass

    def paste_message(self):
        try:
            clipboard_text = self.root.clipboard_get()
            self.input_text.insert(tk.END, clipboard_text)
        except tk.TclError:
            pass

    def quote_message(self):
        try:
            selected_text = self.chat_display.get(tk.SEL_FIRST, tk.SEL_LAST)
            self.input_text.insert(tk.END, "'" + selected_text + "\n")
        except tk.TclError:
            pass

    def restore_session(self):
        if self.last_credentials:
            username, password = self.last_credentials
            login_command = "/login " + str(username) + " " + str(password)
            if self.encryption_enabled:
                self._enc_send(login_command)
            else:
                self.client_socket.send(login_command.encode('utf-8'))
            time.sleep(1)
            
            if self.last_server:
                server_command = "/join_server " + str(self.last_server)
                if self.encryption_enabled:
                    self._enc_send(server_command)
                else:
                    self.client_socket.send(server_command.encode('utf-8'))

    def start_ping_thread(self):
        def ping_loop():
            while not self.stop_event.is_set():
                try:
                    if self.encryption_enabled:
                        self._enc_send("/")
                    else:
                        self.client_socket.send(b"/")
                    self.waiting_ping_response = True
                except Exception:
                    pass
                time.sleep(5)
        threading.Thread(target=ping_loop, daemon=True).start()

    def _pkcs7_pad(self, data_bytes):
        pad_len = 16 - (len(data_bytes) % 16)
        return data_bytes + bytes([pad_len] * pad_len)

    def _pkcs7_unpad(self, data_bytes):
        if not data_bytes:
            return None
        pad_len = data_bytes[-1]
        if pad_len == 0 or pad_len > 16:
            return None
        if data_bytes[-pad_len:] != bytes([pad_len] * pad_len):
            return None
        return data_bytes[:-pad_len]

    def _aes_cbc_encrypt(self, plaintext_utf8):
        iv = os.urandom(16)
        b = plaintext_utf8.encode('utf-8')
        b = self._pkcs7_pad(b)
        aes = pyaes.AESModeOfOperationCBC(self.session_key_enc, iv=iv)
        out = b""
        for i in range(0, len(b), 16):
            out += aes.encrypt(b[i:i+16])
        return iv + out

    def _aes_cbc_decrypt(self, payload_bytes):
        if len(payload_bytes) < 16:
            return None
        iv = payload_bytes[:16]
        enc = payload_bytes[16:]
        if len(enc) % 16 != 0:
            return None
        aes = pyaes.AESModeOfOperationCBC(self.session_key_enc, iv=iv)
        out = b""
        for i in range(0, len(enc), 16):
            out += aes.decrypt(enc[i:i+16])
        unpadded = self._pkcs7_unpad(out)
        if unpadded is None:
            return None
        try:
            return unpadded.decode('utf-8')
        except Exception:
            return None

    def _enc_send(self, msg_text):
        payload = self._aes_cbc_encrypt(msg_text)
        mac = hmac.new(self.session_key_mac, payload, hashlib.sha256).digest()
        packet = payload + mac
        header = struct.pack('>I', len(packet))
        self.client_socket.send(header + packet)

    def _enc_recv(self):
        try:
            self.client_socket.settimeout(0.1)
            header = self._read_exact(4)
            if header is None:
                return None
            total_len = struct.unpack('>I', header)[0]
            data = self._read_exact(total_len)
            if data is None or len(data) < 32:
                return None
            payload = data[:-32]
            mac = data[-32:]
            exp_mac = hmac.new(self.session_key_mac, payload, hashlib.sha256).digest()
            if exp_mac != mac:
                return None
            return self._aes_cbc_decrypt(payload)
        finally:
            self.client_socket.settimeout(self.socket_timeout)

    def _read_exact(self, n):
        buf = b""
        while len(buf) < n:
            try:
                chunk = self.client_socket.recv(n - len(buf))
            except socket.timeout:
                return None
            if not chunk:
                return None
            buf += chunk
        return buf

    def _perform_dh_handshake(self):
        header = self._read_exact(2)
        if header is None:
            raise ConnectionError("Handshake failed: no A length")
        alen = struct.unpack('>H', header)[0]
        Ab = self._read_exact(alen)
        if Ab is None:
            raise ConnectionError("Handshake failed: no A bytes")
        P = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF", 16)
        G = 2
        A = int(binascii.hexlify(Ab).decode('ascii'), 16)
        b = random.getrandbits(256)
        B = pow(G, b, P)
        Bh = hex(B)[2:].rstrip('L')
        if len(Bh) % 2:
            Bh = '0' + Bh
        Bb = binascii.unhexlify(Bh)
        self.client_socket.send(struct.pack('>H', len(Bb)) + Bb)
        S = pow(A, b, P)
        Sh = hex(S)[2:].rstrip('L')
        if len(Sh) % 2:
            Sh = '0' + Sh
        Sb = binascii.unhexlify(Sh)
        self.session_key_enc = hashlib.sha256(Sb + b"|KEY").digest()
        self.session_key_mac = hashlib.sha256(Sb + b"|MAC").digest()

if __name__ == "__main__":
    f = 'server.txt'
    try:
        s, p = [l.split('=')[1].strip() for l in open(f)]
    except FileNotFoundError:
        open(f, 'w').write("server=dmconnect.hoho.ws\nport=42439\n")
        s, p = 'dmconnect.hoho.ws', '42439'

    root = tk.Tk()
    app = DMC(root, s, int(p))
    root.mainloop()
