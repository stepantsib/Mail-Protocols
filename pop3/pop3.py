import argparse
import socket
import ssl
import getpass
import re
import base64


def custom_decode_header(val):
    """
    Декодирует заголовки письма в формате MIME Encoded-Words и Quoted-Printable.
    Полностью независимый парсер, работающий по стандартам RFC 2047.
    """
    if not val: return ""
    val = re.sub(r'(\?=)\s+(=\?)', r'\1\2', str(val))

    def decode_match(m):
        charset, enc, payload = m.group(1).lower(), m.group(2).lower(), m.group(3)
        try:
            if enc == 'b':
                b = base64.b64decode(payload + '===')
            elif enc == 'q':
                payload = payload.replace('_', ' ').encode('ascii')
                b = re.sub(b'=([0-9A-Fa-f]{2})', lambda x: bytes([int(x.group(1), 16)]), payload)
            else:
                return m.group(0)
            return b.decode(charset, 'replace')
        except Exception:
            return m.group(0)

    return re.sub(r'=\?([^?]+)\?([bBqQ])\?([^?]+)\?=', decode_match, val)


def parse_raw_headers(header_bytes):
    """
    Разбирает сырые байты заголовков и собирает их в словарь.
    Учитывает механизм Header Folding (RFC 5322) для длинных строк.
    """
    text = re.sub(r'\r\n([ \t]+)', r' \1', header_bytes.decode('utf-8', 'ignore'))
    return {k.strip().lower(): v.strip() for k, v in re.findall(r'(?m)^([^:]+):(.*)$', text)}


def extract_attachments_from_raw(raw_body_bytes):
    """
    Эвристический поиск вложений в сыром теле письма.
    Поскольку POP3 не поддерживает команду BODYSTRUCTURE (как IMAP), нам
    приходится искать имена файлов (Content-Disposition: attachment; filename="...")
    прямо в скачанных байтах письма с помощью регулярных выражений.
    """
    att = []
    # Ищем name="file.ext" или filename="file.ext"
    matches = re.finditer(rb'(?:name|filename)\s*=\s*(?:"([^"]+)"|([^\s;]+))', raw_body_bytes, re.IGNORECASE)

    for m in matches:
        val = m.group(1) or m.group(2)
        if val:
            fname = custom_decode_header(val.decode('utf-8', 'ignore'))
            # Защита от дубликатов (MIME часто дублирует name и filename)
            if fname and not any(a['name'] == fname for a in att):
                att.append({'name': fname, 'size': 'Скрыто'})  # POP3 не отдает размер частей без их парсинга
    return att


class POP3Client:
    def __init__(self, host, port, use_ssl, verbose=False):
        """
        Инициализирует объект POP3-клиента.
        """
        self.host, self.port, self.use_ssl, self.verbose = host, port, use_ssl, verbose
        self.sock, self.file = None, None

    def send_command(self, cmd, is_sensitive=False, multiline=False, silence_body=False):
        """
        Отправляет команду серверу POP3.
        Если multiline=True, читает строки до получения завершающей точки ('\\r\\n.\\r\\n').
        Реализует снятие byte-stuffing (удаление лишней точки в начале строки).
        """
        full_cmd = cmd + b'\r\n'
        if self.verbose:
            print(f">>> PASS ***" if is_sensitive else f">>> {full_cmd.decode('utf-8', 'replace').strip()}")

        self.sock.sendall(full_cmd)

        # Читаем статусную строку (+OK или -ERR)
        status_line = self.file.readline()
        if self.verbose:
            print(f"<<< {status_line.decode('utf-8', 'replace').strip()}")

        if not status_line.startswith(b'+OK'):
            raise RuntimeError(f"Ошибка команды: {status_line.decode('utf-8', 'replace').strip()}")

        # Читаем многострочный ответ (например, от LIST, RETR, TOP, CAPA)
        if multiline:
            lines = []
            while True:
                line = self.file.readline()
                if not line: break

                # Конец многострочного ответа в POP3 — это одиночная точка
                if line == b'.\r\n':
                    if self.verbose and not silence_body: print("<<< .")
                    break

                # Вывод логов (скрываем длинное тело письма, если silence_body=True)
                if self.verbose and not silence_body:
                    print(f"<<< {line.decode('utf-8', 'replace').strip()}")
                elif self.verbose and silence_body and len(lines) == 0:
                    print("<<< [МНОГОСТРОЧНЫЕ ДАННЫЕ СКРЫТЫ]")

                # Byte-un-stuffing: если строка начинается с '..', убираем первую точку
                if line.startswith(b'..'):
                    line = line[1:]

                lines.append(line)
            return status_line, b''.join(lines)

        return status_line, b''

    def connect(self):
        """
        Устанавливает TCP-соединение с POP3-сервером.
        Порт 995 - неявный SSL. Порт 110 - явный STLS.
        """
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(60)

        if self.use_ssl and self.port == 995:
            self.sock = ssl.create_default_context().wrap_socket(self.sock, server_hostname=self.host)

        self.sock.connect((self.host, self.port))
        self.file = self.sock.makefile('rb')

        greeting = self.file.readline()
        if self.verbose:
            print(f"<<< {greeting.decode('utf-8', 'replace').strip()}")

        if self.use_ssl and self.port != 995:
            try:
                self.send_command(b'STLS')
                self.sock = ssl.create_default_context().wrap_socket(self.sock, server_hostname=self.host)
                self.file = self.sock.makefile('rb')
            except Exception:
                pass  # STLS не поддерживается, продолжаем по открытому каналу

    def login(self, user, password):
        """Авторизация по протоколу POP3 (USER + PASS)."""
        try:
            self.sock.settimeout(120)
            self.send_command(f'USER {user}'.encode())
            self.send_command(f'PASS {password}'.encode(), is_sensitive=True)
            self.sock.settimeout(60)
        except socket.timeout:
            raise RuntimeError("Таймаут авторизации!")

    def stat(self):
        """Узнает количество писем и их общий размер (STAT)."""
        resp, _ = self.send_command(b'STAT')
        parts = resp.split()
        return int(parts[1]) if len(parts) > 1 else 0

    def fetch_info(self, start, end):
        """
        Получает информацию о письмах (размер, заголовки, вложения).
        """
        sz, hdrs, atts = {}, {}, {}

        # 1. Запрашиваем размеры всех писем командой LIST
        _, list_data = self.send_command(b'LIST', multiline=True)
        for line in list_data.split(b'\r\n'):
            if line:
                parts = line.split()
                if len(parts) >= 2:
                    sz[int(parts[0])] = int(parts[1])

        # 2. Скачиваем письма для получения заголовков и поиска вложений
        for i in range(start, end + 1):
            if i not in sz: continue

            # Команда RETR скачивает ВСЁ письмо.
            # Если вложения не нужны, можно использовать "TOP i 0" для загрузки только заголовков.
            _, raw_email = self.send_command(f'RETR {i}'.encode(), multiline=True, silence_body=True)

            # Разделяем заголовки и тело письма (пустая строка \r\n\r\n по RFC)
            header_end = raw_email.find(b'\r\n\r\n')
            if header_end == -1:
                header_end = len(raw_email)

            raw_hdrs = parse_raw_headers(raw_email[:header_end])
            hdrs[i] = {k: custom_decode_header(raw_hdrs.get(k.lower(), '')) for k in ('To', 'From', 'Subject', 'Date')}

            # Ищем вложения в теле письма
            atts[i] = extract_attachments_from_raw(raw_email[header_end:])

        return sz, hdrs, atts


def main():
    parser = argparse.ArgumentParser(description="POP3 Client")
    parser.add_argument('-s', '--server', required=True, help="Сервер в формате адрес[:порт]")
    parser.add_argument('-u', '--user', required=True, help="Имя пользователя")
    parser.add_argument('--ssl', action='store_true', help="Разрешить SSL/STLS")
    parser.add_argument('-n', nargs='+', type=int, help="Диапазон писем N1 [N2]")
    parser.add_argument('-v', '--verbose', action='store_true', help="Отображать протокол")

    args = parser.parse_args()

    # По умолчанию для POP3 используется порт 110 (или 995 для SSL)
    default_port = 995 if args.ssl else 110
    host, port = (args.server.rsplit(':', 1) + [default_port])[:2] if ':' in args.server else (args.server,
                                                                                               default_port)

    pwd = getpass.getpass("Пароль: ").replace(" ", "").strip()

    client = POP3Client(host, int(port), args.ssl, args.verbose)
    try:
        client.connect()
        client.login(args.user, pwd)

        total_msgs = client.stat()
        if total_msgs == 0:
            return print("В почтовом ящике нет писем.")

        start = max(1, args.n[0] if args.n else 1)
        end = min(total_msgs, args.n[1] if args.n and len(args.n) > 1 else (start if args.n else total_msgs))
        if start > end:
            return print(f"Неверный диапазон. Всего писем: {total_msgs}")

        print("\nПолучение данных с сервера (POP3 скачивает письма целиком, это может занять время)...")
        sizes, headers, attachments = client.fetch_info(start, end)

        print(f"\n{'ID':<4} | {'От кого':<25} | {'Кому':<25} | {'Тема':<35} | {'Дата':<20} | {'Размер':<8} | Аттачи")
        print("-" * 150)

        fmt = lambda t, l: (t[:l - 3] + '...') if len(t) > l else t
        for i in range(start, end + 1):
            if i not in headers: continue
            h, s, a = headers[i], sizes.get(i, 0), attachments.get(i, [])
            att_str = f"{len(a)} шт. [{', '.join(f'{at['name']}' for at in a)}]" if a else "Нет"
            print(
                f"{i:<4} | {fmt(h['From'], 25):<25} | {fmt(h['To'], 25):<25} | {fmt(h['Subject'], 35):<35} | {h['Date'][:20]:<20} | {s:<8} | {att_str}")

        client.send_command(b'QUIT')

    except Exception as e:
        print(f"\nОшибка: {e}")


if __name__ == "__main__":
    main()