import argparse
import base64
import getpass
import re
import socket
import ssl


def custom_decode_header(val):
    """
        Декодирует заголовки письма в формате MIME Encoded-Words и Quoted-Printable.
        Вручную находит конструкции вида '=?charset?encoding?text?=' и переводит их из Base64
        или Q-кодировки в читаемую строку с учетом исторического RFC-форматирования
        (например, игнорирование переносов между блоками).
    """
    if not val: return ""
    # Игнорируем пробелы между двумя закодированными словами по RFC
    val = re.sub(r'(\?=)\s+(=\?)', r'\1\2', str(val))

    def decode_match(m):
        charset, enc, payload = m.group(1).lower(), m.group(2).lower(), m.group(3)
        try:
            if enc == 'b':  # Base64 (добавляем '===' для страховки от обрезки padding'а)
                b = base64.b64decode(payload + '===')
            elif enc == 'q':  # Quoted-Printable
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
        Разбирает сырые байты заголовков от сервера и собирает их в словарь.
        Реализует механизм Header Folding (RFC 5322), склеивая строки, разбитые
        переносами '\r\n' с последующим пробелом или табуляцией, чтобы длинные
        заголовки (например, Subject) не обрезались.
    """
    text = re.sub(r'\r\n([ \t]+)', r' \1', header_bytes.decode('utf-8', 'ignore'))
    return {k.strip().lower(): v.strip() for k, v in re.findall(r'(?m)^([^:]+):(.*)$', text)}


def parse_imap_bodystructure(s):
    """
        Строит абстрактное синтаксическое дерево (AST) из LISP-подобного ответа BODYSTRUCTURE.
        Использует регулярное выражение для токенизации строки (разбиения на скобки, слова
        и строки в кавычках) и рекурсивно собирает их во вложенные списки для удобной навигации.
    """

    # Разбиваем строку на 3 типа токенов: Строки в кавычках | Скобки | Слова без пробелов
    tokens = re.findall(r'"(?:\\.|[^"\\])*"|[()]|[^\s()]+', s)

    def build(it):
        res = []
        for t in it:
            if t == '(':
                res.append(build(it))
            elif t == ')':
                return res
            elif t.upper() == 'NIL':
                res.append(None)
            else:
                res.append(t.strip('"').replace('\\"', '"'))  # Убираем кавычки
        return res

    ast = build(iter(tokens))
    return ast[0] if ast else []


def extract_attachments(ast):
    """
        Рекурсивно обходит AST-дерево структуры письма для поиска вложений.
        Проверяет наличие ключей 'name' или 'filename' в параметрах узлов и извлекает
        название файла (сразу применяя к нему декодирование MIME) и его размер в байтах.
    """

    def find_name(lst):
        # Ищет 'name' или 'filename' в любых вложенных параметрах
        if isinstance(lst, list):
            for i in range(len(lst) - 1):
                if str(lst[i]).lower() in ('name', 'filename') and isinstance(lst[i + 1], str):
                    return custom_decode_header(lst[i + 1])
            for item in lst:
                res = find_name(item)
                if res: return res
        return None

    att = []
    if isinstance(ast, list) and ast:
        if isinstance(ast[0], str):  # Это конечный узел (MIME-часть)
            fname = find_name(ast)
            if fname:
                size = ast[6] if len(ast) > 6 and str(ast[6]).isdigit() else 0
                att.append({'name': fname, 'size': size})
        else:  # Это составной узел (multipart), идем глубже
            for item in ast:
                att.extend(extract_attachments(item))
    return att


class IMAPClient:
    def __init__(self, host, port, use_ssl, verbose=False):
        """
            Инициализирует объект IMAP-клиента.
            Задает базовые параметры подключения и создает счетчик тегов tag_counter
            для формирования уникальных идентификаторов команд (A001, A002...).
        """
        self.host, self.port, self.use_ssl, self.verbose = host, port, use_ssl, verbose
        self.sock, self.file, self.tag_counter = None, None, 1

    def send_command(self, cmd, is_sensitive=False):
        """
            Отправляет команду на сервер и читает многострочный ответ.
            Автоматически генерирует уникальный тег, прикрепляет его к запросу и накапливает
            ответ, корректно обрабатывая IMAP Literals ({размер}\r\n). При включенном verbose
            скрывает чувствительные данные (пароли) в логах.
        """
        tag = f"A{self.tag_counter:03d}".encode()
        self.tag_counter += 1
        full_cmd = tag + b' ' + cmd + b'\r\n'

        if self.verbose:
            print(
                f">>> {tag.decode()} LOGIN \"***\" \"***\"" if is_sensitive else f">>> "
                                                                                 f"{full_cmd.decode('utf-8', 'replace').strip()}")
        self.sock.sendall(full_cmd)

        lines = []
        while True:
            line = self.file.readline()
            if not line: break
            if self.verbose and not line.startswith((b'* BODY', b'* FETCH')):
                print(f"<<< {line.decode('utf-8', 'replace').strip()}")

            lit_match = re.search(rb'\{(\d+)\+?\}\r\n$', line)
            if lit_match:  # Обработка IMAP Literals
                lines.extend([line, self.file.read(int(lit_match.group(1)))])
                continue

            lines.append(line)
            if line.startswith(tag): break
        return b''.join(lines)

    def connect(self):
        """
            Устанавливает TCP-соединение с IMAP-сервером.
            Поддерживает неявный SSL при подключении к порту 993. Для стандартных портов
            запрашивает возможности сервера (CAPABILITY) и при наличии STARTTLS переводит
            открытое соединение в защищенный TLS-контекст.
        """
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(60)
        if self.use_ssl and self.port == 993:
            self.sock = ssl.create_default_context().wrap_socket(self.sock, server_hostname=self.host)

        self.sock.connect((self.host, self.port))
        self.file = self.sock.makefile('rb')
        if self.verbose:
            print(f"<<< {self.file.readline().decode('utf-8', 'replace').strip()}")

        if self.use_ssl and self.port != 993:  # Явный STARTTLS
            if b'STARTTLS' in self.send_command(b'CAPABILITY'):
                if b'OK' in self.send_command(b'STARTTLS').split(b'\r\n')[-2]:
                    self.sock = ssl.create_default_context().wrap_socket(self.sock, server_hostname=self.host)
                    self.file = self.sock.makefile('rb')

    def fetch_info(self, start, end):
        """
            Запрашивает у сервера информацию о диапазоне писем.
            Отправляет три последовательные команды FETCH. Использует кастомные парсеры
            для распаковки сырых байтов заголовков, их декодирования и извлечения
            данных о файлах вложениях из структуры BODYSTRUCTURE.
        """
        sz, hdrs, atts = {}, {}, {}
        # 1. Запрашиваем размеры
        for m in re.finditer(rb'\* (\d+) FETCH .*?RFC822\.SIZE (\d+)',
                             self.send_command(f'FETCH {start}:{end} RFC822.SIZE'.encode())):
            sz[int(m.group(1))] = int(m.group(2))

        # 2. Запрашиваем заголовки
        for blk in self.send_command(f'FETCH {start}:{end} BODY.PEEK[HEADER]'.encode()).split(b'* '):
            m = re.search(rb'(\d+)\s+FETCH.*?\{(\d+)\+?\}\r\n', blk)
            if m:
                mid, size = int(m.group(1)), int(m.group(2))
                raw_hdrs = parse_raw_headers(blk[m.end(): m.end() + size])
                hdrs[mid] = {k: custom_decode_header(raw_hdrs.get(k.lower(), '')) for k in
                             ('To', 'From', 'Subject', 'Date')}

        # 3. Запрашиваем структуру (BODYSTRUCTURE)
        for blk in self.send_command(f'FETCH {start}:{end} BODYSTRUCTURE'.encode()).split(b'* '):
            m = re.search(rb'(\d+)\s+FETCH', blk)
            idx = blk.find(b'BODYSTRUCTURE')
            if m and idx != -1:
                ast = parse_imap_bodystructure(blk[blk.find(b'(', idx):].decode('utf-8', 'ignore'))
                atts[int(m.group(1))] = extract_attachments(ast)

        return sz, hdrs, atts


def main():
    """
        Точка входа в программу.
        Обрабатывает аргументы командной строки, скрыто запрашивает пароль,
        устанавливает защищенную сессию с сервером и выводит красиво отформатированную
        таблицу со списком писем в консоль.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--server', required=True)
    parser.add_argument('-u', '--user', required=True)
    parser.add_argument('--ssl', action='store_true')
    parser.add_argument('-n', nargs='+', type=int)
    parser.add_argument('-v', '--verbose', action='store_true')
    args = parser.parse_args()

    host, port = (args.server.rsplit(':', 1) + [143])[:2] if ':' in args.server else (args.server, 143)
    pwd = getpass.getpass("Пароль: ").replace(" ", "").strip()

    client = IMAPClient(host, int(port), args.ssl, args.verbose)
    try:
        client.connect()
        try:
            client.sock.settimeout(120)
            if b"OK" not in client.send_command(f'LOGIN "{args.user}" "{pwd}"'.encode(), True).split(b'\r\n')[-2]:
                raise RuntimeError("Ошибка авторизации")
            client.sock.settimeout(60)
        except socket.timeout:
            raise RuntimeError("Таймаут авторизации! Google заморозил соединение.")

        m = re.search(rb'\* (\d+) EXISTS', client.send_command(b'SELECT INBOX'))
        total_msgs = int(m.group(1)) if m else 0
        if total_msgs == 0: return print("В ящике INBOX нет писем.")

        start = max(1, args.n[0] if args.n else 1)
        end = min(total_msgs, args.n[1] if args.n and len(args.n) > 1 else (start if args.n else total_msgs))
        if start > end: return print(f"Неверный диапазон. Всего писем: {total_msgs}")

        print("\nПолучение данных с сервера...\n")
        sizes, headers, attachments = client.fetch_info(start, end)

        print(f"{'ID':<4} | {'От кого':<25} | {'Кому':<25} | {'Тема':<35} | {'Дата':<20} | {'Размер':<8} | Аттачи")
        print("-" * 150)

        fmt = lambda t, l: (t[:l - 3] + '...') if len(t) > l else t
        for i in range(start, end + 1):
            if i not in headers: continue
            h, s, a = headers[i], sizes.get(i, 0), attachments.get(i, [])
            att_str = f"{len(a)} шт. [{', '.join(f'{at['name']} ({at['size']}B)' for at in a)}]" if a else "Нет"
            print(
                f"{i:<4} | {fmt(h['From'], 25):<25} | {fmt(h['To'], 25):<25} | {fmt(h['Subject'], 35):<35} | "
                f"{h['Date'][:20]:<20} | {s:<8} | {att_str}")

    except Exception as e:
        print(f"\nОшибка: {e}")


if __name__ == "__main__":
    main()
