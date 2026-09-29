# socks2tun

«Обратный tun2socks»: SOCKS5-сервер, который превращает соединения клиентов в сырые IPv4-пакеты на дескрипторе, который TUN-only ядро считает своим TUN-устройством.

Нужен, когда ядро туннеля (например, [CSQTT](https://github.com/amurcanov/csqtt)) умеет только читать и писать IP-пакеты в дескриптор TUN, а приложению (Xray, hev-socks5-tunnel, браузер, `curl`) нужен локальный SOCKS5. Проект не привязан к CSQTT: подойдёт любое ядро, которое принимает дескриптор по протоколу `--tun-uds` или наследует его через `--fd`.

```
Xray / curl / hev-socks5-tunnel
        │  SOCKS5 (CONNECT, UDP ASSOCIATE)
        ▼
socks2tun:  SOCKS5-сервер ─▶ userspace-стек gVisor (адрес туннеля /32)
        │  сырые IPv4-пакеты, socketpair(AF_UNIX, SOCK_SEQPACKET)
        ▼  один пакет = одно read/write
ядро (CSQTT и т. п.): дескриптор считает своим TUN ─▶ туннель ─▶ сервер
```

1. socks2tun создаёт `socketpair(AF_UNIX, SOCK_SEQPACKET)`: границы пакетов сохраняются, одно `read`/`write` — один IP-пакет.
2. Один конец отдаёт ядру (`--tun-uds`), со вторым работает как с TUN-устройством.
3. На своём конце поднимает userspace-стек gVisor с одним NIC (point-to-point, IPv4, адрес туннеля /32).
4. Каждый SOCKS5 CONNECT — TCP-соединение, открытое из стека с адреса туннеля; UDP ASSOCIATE — UDP-сокет в стеке.
5. Доменные имена резолвятся через DNS туннеля по этому же стеку (UDP, при неудаче или усечении — TCP), с кэшем по TTL. Системный резолвер не используется.

## Сборка

Нужен Go 1.26.3+ (см. `go.mod`).

```sh
go build .                                         # для текущей ОС (Linux)

# Android arm64-v8a
CGO_ENABLED=0 GOOS=android GOARCH=arm64 go build -trimpath -ldflags="-s -w -checklinkname=0" -o libsocks2tun.so .

# armeabi-v7a, x86, x86_64 — статические Linux-бинарники (запускаются на Android)
CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -trimpath -ldflags="-s -w -checklinkname=0" -o libsocks2tun.so .
CGO_ENABLED=0 GOOS=linux GOARCH=386         go build -trimpath -ldflags="-s -w -checklinkname=0" -o libsocks2tun.so .
CGO_ENABLED=0 GOOS=linux GOARCH=amd64       go build -trimpath -ldflags="-s -w -checklinkname=0" -o libsocks2tun.so .
```

> **Почему не `GOOS=android` для всех ABI.** Тулчейн Go без cgo умеет линковать для Android только `arm64`: для `android/arm`, `android/386` и `android/amd64` он требует внешнюю (cgo) линковку и с `CGO_ENABLED=0` завершается ошибкой `requires external (cgo) linking`. Статический `GOOS=linux`-бинарник работает на Android так же (ядро то же, системный резолвер и libc не используются). Альтернатива — `CGO_ENABLED=1` с NDK-компилятором в `CC`.

`libsocks2tun.so` — исполняемый файл, а не библиотека: такое имя позволяет положить его в `jniLibs` и запускать из `nativeLibraryDir`.

## Флаги

| Флаг | По умолчанию | Описание |
|---|---|---|
| `--listen` | `127.0.0.1:1080` | адрес SOCKS5 |
| `--tun-uds <name>` | — | абстрактный Unix-сокет ядра, которому передаётся дескриптор |
| `--fd <N>` | — | использовать унаследованный дескриптор пакетов вместо `--tun-uds` |
| `--ip` | — | IPv4 туннеля (можно задать позже через stdin) |
| `--dns` | — | DNS туннеля через запятую (можно задать позже через stdin) |
| `--mtu` | `1280` | MTU туннеля (576–65535) |
| `--user`, `--pass` | — | логин/пароль (RFC 1929); если заданы, без них не пускает |
| `--uds-timeout` | `60s` | сколько пытаться передать дескриптор ядру (`0` — бесконечно) |
| `--connect-timeout` | `15s` | таймаут DNS + TCP connect |
| `--tcp-idle` | `5m` | таймаут простоя CONNECT (`0` — без таймаута) |
| `--udp-idle` | `2m` | таймаут простоя UDP ASSOCIATE (`0` — без таймаута) |
| `--max-conns` | `1024` | лимит одновременных SOCKS5-соединений (`0` — без лимита) |
| `--debug` | выкл. | подробные строки по соединениям (но не по пакетам) |
| `--version` | | версия |

Нужен ровно один из `--tun-uds` и `--fd`.

## Протокол `--tun-uds`

Совместим с `FdReceiver` из CSQTT (`rust-client/tun.rs`). Ядро слушает **абстрактный** Unix-сокет `name` (SOCK_STREAM), socks2tun:

1. подключается к `@name`;
2. отправляет `sendmsg`: 1 байт данных `0x01` + `SCM_RIGHTS` с одним дескриптором (конец socketpair для ядра);
3. ждёт 1 байт подтверждения (до 5 с), после чего закрывает свою копию дескриптора ядра.

Если ядро ещё не запущено, подключение повторяется каждые 250 мс, пока не истечёт `--uds-timeout` (ошибки логируются без повторов одного и того же чаще раза в 5 с). Если ядро закрыло свой конец (например, перезапустилось), socks2tun создаёт новую пару и снова отдаёт её по тому же протоколу: NIC, адрес и SOCKS5-сервер при этом не пересоздаются. CSQTT принимает такую замену без перезапуска.

## Управление через stdin

Команды построчно, применяются на ходу:

```
ip 10.0.0.2          # адрес туннеля (/32 можно указать, "ip none" — снять адрес)
dns 1.1.1.1,8.8.8.8  # DNS туннеля (через запятую или пробел; "dns none" — очистить)
mtu 1400             # MTU для новых соединений
ip 10.0.0.2 dns 1.1.1.1 mtu 1300   # несколько команд в одной строке
```

Также принимается строка из лога CSQTT: `... Tunnel IP: 10.0.0.2/32 | DNS: 1.1.1.1`.

- Пока адреса нет, SOCKS5 уже слушает, но CONNECT и UDP ASSOCIATE получают ответ `0x03` (network unreachable), а в лог пишется `no tunnel address yet` (не чаще раза в секунду).
- При смене адреса соединения, открытые со старого адреса, закрываются.
- Смена DNS сбрасывает DNS-кэш.
- Закрытие stdin ни на что не влияет.

## SOCKS5

- RFC 1928 и RFC 1929; методы: без аутентификации или логин/пароль.
- Команды: CONNECT и UDP ASSOCIATE. На BIND и неизвестные команды — `0x07`.
- Адреса: IPv4 и доменные имена. IPv6 — `0x08` (туннель только IPv4).
- UDP ASSOCIATE: relay открывается на том IP, на который пришло TCP-управление, и принимает датаграммы только от IP клиента (и от порта из запроса, если он не `0`). Датаграммы с `FRAG≠0` отбрасываются. Ассоциация живёт, пока жив TCP-контроль, но не дольше `--udp-idle` без трафика.
- Коды ответов: `0x03` — нет адреса туннеля; `0x04` — имя не резолвится или хост недоступен; `0x05` — connection refused; `0x06` — таймаут соединения; `0x01` — прочее.
- Half-close пробрасывается в обе стороны (FIN клиента → FIN в туннель и обратно).
- Паника в обработчике соединения логируется и не роняет процесс; SIGTERM/SIGINT — аккуратное завершение (закрыть слушатель и соединения, выход с кодом 0).

## Логи

Одна строка на событие, префикс `[S2T]`, всё в stderr:

```
[S2T] socks5 listening on 127.0.0.1:1080
[S2T] tun fd sent to @csqtt-tun
[S2T] tun fd send failed: connect @csqtt-tun: connection refused
[S2T] address 10.0.0.2/32 dns 1.1.1.1 mtu 1280
[S2T] address none dns none mtu 1280          # при старте, пока адреса нет
[S2T] no tunnel address yet
[S2T] error: ...
[S2T] debug: ...                               # только с --debug
[S2T] stopped
```

Строки на каждый пакет не пишутся даже с `--debug`.

## Пример: Linux + CSQTT

CSQTT в этот репозиторий не входит (лицензия PolyForm Noncommercial), его нужно собрать отдельно из [amurcanov/csqtt](https://github.com/amurcanov/csqtt).

```sh
# 1. Клиент CSQTT в TUN-режиме: он слушает @csqtt-tun и ждёт дескриптор.
./client <параметры подключения> --tun-uds csqtt-tun

# 2. socks2tun: отдаёт дескриптор и слушает SOCKS5.
./socks2tun --tun-uds csqtt-tun --listen 127.0.0.1:1080

# 3. Когда CSQTT напечатает "Tunnel IP: X/32 | DNS: Y", ввести в stdin socks2tun:
ip X
dns Y

# 4. Проверка: должен показать IP сервера CSQTT.
curl --socks5-hostname 127.0.0.1:1080 https://api.ipify.org
```

Шаги 1–3 можно соединить конвейером: адрес и DNS попадут в socks2tun сами, в том числе после переподключения.

```sh
./client <параметры подключения> --tun-uds csqtt-tun 2>&1 \
  | grep --line-buffered 'Tunnel IP:' \
  | ./socks2tun --tun-uds csqtt-tun --listen 127.0.0.1:1080
```

## Тесты

```sh
go test ./...          # на Linux; с -race нужен cgo
```

- `internal/socks5` — рукопожатие, аутентификация, коды ответов, half-close, UDP ASSOCIATE, лимит соединений, таймауты, паника в обработчике.
- `internal/resolver` — разбор DNS, откат на TCP, кэш, объединение одновременных запросов.
- `internal/tunlink` — протокол `--tun-uds`: получение дескриптора, ack, повторные попытки, замена дескриптора.
- `internal/app` — сквозной тест без реального ядра: второй конец socketpair обслуживает «серверный» gVisor-стек (TCP/UDP-эхо, DNS). Проверяются CONNECT по IP и по имени, объёмная передача с half-close, UDP ASSOCIATE с фрагментацией, ошибки, смена адреса и MTU через stdin и замена дескриптора через `--tun-uds`.

## Ограничения

Только IPv4. Нет BIND, HTTP-прокси, собственного TUN-интерфейса в ОС; поддерживаются только Linux и Android.

## Лицензия

[GPL-3.0](LICENSE).
