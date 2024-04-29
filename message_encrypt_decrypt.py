from tkinter import *
import base64
import time
from tkinter import filedialog
import socket

root = Tk()
root.geometry("1000x600")
root.title("Message Encryption and Document Encryption")

Tops = Frame(root, width=1600, relief=SUNKEN, bg="#4285F4")
Tops.pack(side=TOP, fill=X)

f1 = Frame(root, width=800, height=700, relief=SUNKEN, bg="#f9fbe7")
f1.pack(side=LEFT, fill=BOTH, expand=True)

localtime = time.asctime(time.localtime(time.time()))

lblInfo = Label(Tops, font=('Helvetica', 50, 'bold'), text="SECRET MESSAGING \n Vigenère cipher", fg="white", bd=10,
                anchor='w', bg="#4285F4")
lblInfo.grid(row=0, column=0, sticky="w")

lblInfo = Label(Tops, font=('Arial', 20, 'bold'), text=localtime, fg="white", bd=10, anchor='w', bg="#4285F4")
lblInfo.grid(row=1, column=0, sticky="w")
rand = StringVar()
Msg = StringVar()
key = StringVar()
mode = StringVar()
Result = StringVar()
RecipientIP = StringVar()
RecipientPort = StringVar()


def qExit():
    root.destroy()


def Reset():
    rand.set("")
    Msg.set("")
    key.set("")
    mode.set("")
    Result.set("")
    RecipientIP.set("")
    RecipientPort.set("")


def encode_message():
    message = Msg.get()
    encryption_key = key.get()
    mode_val = mode.get()

    if mode_val != 'e':
        Result.set("Invalid mode! Please enter 'e' for encryption.")
        return

    encoded_message = ""
    for i in range(len(message)):
        char = message[i]
        key_char = encryption_key[i % len(encryption_key)]
        encoded_char = chr((ord(char) + ord(key_char)) % 256)
        encoded_message += encoded_char
    Result.set(base64.b64encode(encoded_message.encode()).decode())


def decode_message():
    encoded_message = Msg.get()
    encryption_key = key.get()
    mode_val = mode.get()

    if mode_val != 'd':
        Result.set("Invalid mode! Please enter 'd' for decryption.")
        return

    decoded_message = ""
    try:
        decoded_message = base64.b64decode(encoded_message).decode()
    except base64.binascii.Error:
        Result.set("Invalid base64-encoded message!")
        return

    decrypted_message = ""
    for i in range(len(decoded_message)):
        char = decoded_message[i]
        key_char = encryption_key[i % len(encryption_key)]
        decrypted_char = chr((ord(char) - ord(key_char)) % 256)
        decrypted_message += decrypted_char
    Result.set(decrypted_message)



def encrypt_document():
    file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
    if file_path:
        encryption_key = key.get()

        with open(file_path, "r") as file:
            document = file.read()

        encoded_document = ""
        for i in range(len(document)):
            char = document[i]
            key_char = encryption_key[i % len(encryption_key)]
            encoded_char = chr((ord(char) + ord(key_char)) % 256)
            encoded_document += encoded_char

        encrypted_file_path = filedialog.asksaveasfilename(defaultextension=".txt")
        if encrypted_file_path:
            with open(encrypted_file_path, "w") as file:
                file.write(encoded_document)

            print("Document encrypted and saved successfully!")


def decrypt_document():
    file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
    if file_path:
        decryption_key = key.get()

        with open(file_path, "r") as file:
            encoded_document = file.read()

        decoded_document = ""
        for i in range(len(encoded_document)):
            char = encoded_document[i]
            key_char = decryption_key[i % len(decryption_key)]
            decoded_char = chr((ord(char) - ord(key_char)) % 256)
            decoded_document += decoded_char

        decrypted_file_path = filedialog.asksaveasfilename(defaultextension=".txt")
        if decrypted_file_path:
            with open(decrypted_file_path, "w") as file:
                file.write(decoded_document)

            print("Document decrypted and saved successfully!")


def save_encrypted_message():
    encrypted_message = Result.get()
    encryption_key = key.get()
    if encrypted_message:
        file_path = filedialog.asksaveasfilename(defaultextension=".txt")
        if file_path:
            with open(file_path, "w") as file:
                file.write(f"Name: {rand.get()}\n")
                file.write(f"Encryption Key: {encryption_key}\n")
                file.write(f"Encrypted Message: {encrypted_message}\n")
                file.write(f"Time Encrypted: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}\n")
            send_option = input("Do you want to send the encrypted message to another user? (y/n): ")
            if send_option.lower() == 'y':
                send_message()


def send_message():
    # Get the recipient's IP address and port number from the respective text variables
    ip_address = RecipientIP.get()
    port = int(RecipientPort.get())

    # Create a socket object
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        # Connect to the recipient
        s.connect((ip_address, port))

        # Get the encrypted message and encryption key from the respective variables
        encrypted_message = Result.get()
        encryption_key = key.get()

        # Send the encrypted message and encryption key to the recipient
        message_with_key = f"{encrypted_message}###{encryption_key}"
        s.sendall(message_with_key.encode())

        print("Message sent successfully!")
    except ConnectionRefusedError:
        print("Connection refused. Please make sure the recipient is running the receiving program.")
    finally:
        # Close the socket
        s.close()


lblReference = Label(f1, font=('Arial', 16, 'bold'), text="Name:", bd=16, anchor="w", bg="#f9fbe7")  # New background color
lblReference.grid(row=0, column=0, sticky="w")

txtReference = Entry(f1, font=('Arial', 16, 'bold'), textvariable=rand, bd=10, insertwidth=4, bg="powder blue",
                     justify='right')
txtReference.grid(row=0, column=1)

lblMsg = Label(f1, font=('Arial', 16, 'bold'), text="MESSAGE", bd=16, anchor="w", bg="#f9fbe7")  # New background color
lblMsg.grid(row=1, column=0, sticky="w")

txtMsg = Entry(f1, font=('Arial', 16, 'bold'), textvariable=Msg, bd=10, insertwidth=4, bg="powder blue",
               justify='right')
txtMsg.grid(row=1, column=1)
txtMsg.bind("<Button-3>", lambda e: txtMsg.event_generate("<<Paste>>"))

txtMsg.grid(row=1, column=1)

lblkey = Label(f1, font=('Arial', 16, 'bold'), text="KEY", bd=16, anchor="w", bg="#f9fbe7")  # New background color
lblkey.grid(row=2, column=0, sticky="w")

txtkey = Entry(f1, font=('Arial', 16, 'bold'), textvariable=key, bd=10, insertwidth=4, bg="powder blue",
               justify='right')
txtkey.grid(row=2, column=1)

lblmode = Label(f1, font=('Arial', 16, 'bold'), text="MODE (e for encrypt, d for decrypt):", bd=16, anchor="w",
                bg="#f9fbe7")  # New background color
lblmode.grid(row=3, column=0, sticky="w")

txtmode = Entry(f1, font=('Arial', 16, 'bold'), textvariable=mode, bd=10, insertwidth=4, bg="powder blue",
                justify='right')
txtmode.grid(row=3, column=1)

lblRecipientIP = Label(f1, font=('Arial', 16, 'bold'), text="Recipient's IP Address:", bd=16, anchor="w",
                       bg="#f9fbe7")
lblRecipientIP.grid(row=4, column=0, sticky="w")

txtRecipientIP = Entry(f1, font=('Arial', 16, 'bold'), textvariable=RecipientIP, bd=10, insertwidth=4, bg="powder blue",
                       justify='right')
txtRecipientIP.grid(row=4, column=1)

lblRecipientPort = Label(f1, font=('Arial', 16, 'bold'), text="Recipient's Port Number:", bd=16, anchor="w",
                         bg="#f9fbe7")
lblRecipientPort.grid(row=5, column=0, sticky="w")

txtRecipientPort = Entry(f1, font=('Arial', 16, 'bold'), textvariable=RecipientPort, bd=10, insertwidth=4,
                         bg="powder blue", justify='right')
txtRecipientPort.grid(row=5, column=1)

lblService = Label(f1, font=('Arial', 16, 'bold'), text="The Result-", bd=16, anchor="w", bg="#f9fbe7")  # New background color
lblService.grid(row=2, column=2, sticky="w")

txtService = Entry(f1, font=('Arial', 16, 'bold'), textvariable=Result, bd=10, insertwidth=4, bg="powder blue", justify='right', exportselection=False)

txtService.grid(row=2, column=3)

btnEncode = Button(f1, padx=16, pady=8, bd=16, fg="black", font=('Arial', 16, 'bold'), width=10,
                   text="Encode", bg="powder blue", command=encode_message)
btnEncode.grid(row=6, column=0)

btnDecode = Button(f1, padx=16, pady=8, bd=16, fg="black", font=('Arial', 16, 'bold'), width=10,
                   text="Decode", bg="powder blue", command=decode_message)
btnDecode.grid(row=6, column=1)

btnReset = Button(f1, padx=16, pady=8, bd=16, fg="black", font=('Arial', 16, 'bold'), width=10,
                  text="Reset", bg="green", command=Reset)
btnReset.grid(row=9, column=2, sticky="e")

btnExit = Button(f1, padx=16, pady=8, bd=16, fg="black", font=('Arial', 16, 'bold'), width=10,
                 text="Exit", bg="red", command=qExit)
btnExit.grid(row=9, column=3, sticky="w")


btnEncryptDoc = Button(f1, padx=16, pady=8, bd=16, fg="black", font=('Arial', 16, 'bold'), width=15,
                       text="Encrypt Document", bg="#4285F4", command=encrypt_document)  # New background color
btnEncryptDoc.grid(row=7, column=0, sticky="w")

btnDecryptDoc = Button(f1, padx=16, pady=8, bd=16, fg="black", font=('Arial', 16, 'bold'), width=15,
                       text="Decrypt Document", bg="#4285F4", command=decrypt_document)  # New background color
btnDecryptDoc.grid(row=7, column=1, sticky="w")

btnSaveEncrypted = Button(f1, padx=16, pady=8, bd=16, fg="black", font=('Arial', 16, 'bold'), width=15,
                          text="Save ", bg="#4285F4", command=save_encrypted_message)  # New background color
btnSaveEncrypted.grid(row=8, column=0, sticky="w")

btnSend = Button(f1, padx=16, pady=8, bd=16, fg="black", font=('Arial', 16, 'bold'), width=15,
                 text="Send Message", bg="#4285F4", command=send_message)  # New background color
btnSend.grid(row=8, column=1, sticky="w")

root.mainloop()