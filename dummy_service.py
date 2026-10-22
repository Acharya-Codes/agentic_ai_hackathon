import socket
import threading
HOST = "0.0.0.0"  
PORT = 2323
BANNER = b"FakeCam v1.0 (demo device)\r\nlogin: "
def handle(client, addr):
    try:
        client.sendall(BANNER)
    finally:
        client.close()
def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(5)
    print(f"Dummy risky service listening on {HOST}:{PORT} (Ctrl+C to stop)")
    try:
        while True:
            client, addr = server.accept()
            threading.Thread(target=handle, args=(client, addr), daemon=True).start()
    except KeyboardInterrupt:
        print("\nStopping dummy service.")
    finally:
        server.close()
if __name__ == "__main__":
    main()