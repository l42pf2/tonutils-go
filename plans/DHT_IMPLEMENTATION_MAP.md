# Карта реализации DHT сервера в проекте TON (https://github.com/ton-blockchain/ton)

## Подробная карта реализации

### Публичный интерфейс — `dht/dht.h`
Абстрактный класс `Dht` (наследует `td::actor::Actor`):
- **`create()`** — создаёт полноценный DHT-узел
- **`create_client()`** — создаёт только клиентский узел (без приёма запросов)
- **`set_value()`** / **`get_value()`** / **`get_value_many()`** — операции с DHT-хранилищем
- **`register_reverse_connection()`** / **`request_reverse_ping()`** — поддержка обратных соединений (reverse NAT traversal)

### Конфигурация — `dht/dht.hpp` (`DhtGlobalConfig`)
Параметры:
- **`k`** — размер k-bucket (по умолчанию 10, макс 10)
- **`a`** — параллелизм запросов (по умолчанию 3, макс 10)
- **`network_id`** — идентификатор сети
- **`static_nodes`** — начальные bootstrap-узлы

### Реализация — `dht/dht-in.hpp` + `dht/dht.cpp` (`DhtMemberImpl`)

**Хранилище:**
- `values_` — локальное DHT-хранилище (`map<DhtKeyId, DhtValue>`)
- `our_values_` — свои значения для переиздания
- `buckets_[256]` — Kademlia buckets (один на каждый бит XOR-расстояния)
- Персистентность через RocksDB в `db_root_`

**Обрабатываемые запросы** (через ADNL):

| Запрос | Метод | Описание |
|--------|-------|----------|
| `dht_ping` | `process_query` | Пинг |
| `dht_findNode` | `process_query` | Найти ближайшие узлы |
| `dht_findValue` | `process_query` | Найти значение или ближайшие узлы |
| `dht_store` | `process_query` | Сохранить значение |
| `dht_getSignedAddressList` | `process_query` | Получить адрес узла |
| `dht_registerReverseConnection` | `process_query` | Зарегистрировать обратное соединение |
| `dht_requestReversePing` | `process_query` | Запросить обратный пинг |

**Периодические задачи** (`alarm()` каждую секунду):
- Удаление устаревших значений (TTL)
- Переиздание своих значений (`our_values_`)
- Поиск случайных ключей для заполнения routing table (`fill_att_`)
- Сохранение bucket'ов в RocksDB

### Типы данных — `dht/dht-types.h`
- `DhtKeyId` — 256-битный хеш ключа (операции XOR для Kademlia)
- `DhtKey` — `{PublicKeyHash, name, index}` → вычисляет `DhtKeyId`
- `DhtValue` — `{DhtKeyDescription, data, ttl, signature}`, макс 768 байт
- `DhtUpdateRule` — правила обновления: `Signature`, `Anybody`, `OverlayNodes`

### DHT-сервер (демон) — `dht-server/dht-server.hpp`
Класс `DhtServer` — точка входа для standalone DHT-демона:
- Управляет несколькими DHT-узлами (`dht_nodes_`)
- Поднимает ADNL (`adnl_network_manager_`, `adnl_`)
- Имеет control interface для управления через `AdnlExtServer`
- Команды: добавить/удалить ADNL-узел, DHT-узел, импорт/экспорт ключей

---

## Файлы для реализации DHT сервера

### Ядро DHT-протокола

| Файл | Что содержит |
|------|-------------|
| `dht/dht.h` | Публичный интерфейс `Dht` — методы `create`, `set_value`, `get_value`, `get_value_many`, `register_reverse_connection`, `request_reverse_ping` |
| `dht/dht.hpp` | `DhtGlobalConfig` (параметры k/a/network_id/bootstrap-узлы), абстрактный `DhtMember` с константами |
| `dht/dht-in.hpp` | Полная реализация `DhtMemberImpl` — поля, callback, обработчики запросов, константы `MAX_VALUES=100000`, `MAX_REVERSE_CONNECTIONS=100000` |
| `dht/dht.cpp` | Реализация всех методов: `start_up`, `process_query` (ping/findNode/findValue/store/getSignedAddressList/registerReverseConnection/requestReversePing), `check`, `send_store`, `get_nearest_nodes`, `distance`, `save_to_db` |

### Типы данных

| Файл | Что содержит |
|------|-------------|
| `dht/dht-types.h` | `DhtKeyId` (256-бит XOR), `DhtKey` (hash+name+idx), `DhtValue` (TTL≤3600+60, data≤768 байт), `DhtKeyDescription`, `DhtUpdateRule`, три правила: `Signature`, `Anybody`, `OverlayNodes` |
| `dht/dht-types.cpp` | Реализация типов: вычисление key_id через SHA256 TL-объекта, проверка подписей, логика merge для OverlayNodes, TTL-приоритет для Signature |

### Routing table (Kademlia buckets)

| Файл | Что содержит |
|------|-------------|
| `dht/dht-bucket.hpp` | `DhtBucket` — 256 bucket'ов, `active_nodes_` и `backup_nodes_` размером k, методы `add_full_node`, `get_nearest_nodes`, `check`, `receive_ping` |
| `dht/dht-bucket.cpp` | Логика продвижения/деградации узлов, выбор backup-узла для вытеснения |
| `dht/dht-remote-node.hpp` | `DhtRemoteNode` — состояние удалённого узла: `missed_pings`, `last_ping_at`, `ready_from`, `failed_from`, интервал пинга |
| `dht/dht-remote-node.cpp` | Логика пинга удалённых узлов, обновление состояния |

### Узлы DHT

| Файл | Что содержит |
|------|-------------|
| `dht/dht-node.hpp` | `DhtNode` — узел DHT (AdnlNodeIdFull + addr_list + version + network_id + signature), сериализация TL, `DhtNodesList` |
| `dht/dht-node.cpp` | Проверка подписи узла, обновление (`update`), логика network_id в сигнатуре |

### Активные запросы (Kademlia lookup)

| Файл | Что содержит |
|------|-------------|
| `dht/dht-query.hpp` | Иерархия query-акторов: `DhtQuery` (базовый, итеративный lookup с параллелизмом `a`), `DhtQueryFindNodes`, `DhtQueryFindValue`, `DhtQueryFindValueSingle`, `DhtQueryFindValueMany`, `DhtQueryStore`, `DhtQueryRegisterReverseConnection`, `DhtQueryRequestReversePing` |
| `dht/dht-query.cpp` | Реализация итеративного поиска: `send_queries`, `add_nodes`, `finish_query`, `MAX_ATTEMPTS=1` |

### TL-схема протокола (wire format)

| Файл | Что содержит |
|------|-------------|
| `tl/generate/scheme/ton_api.tl` | **Главный источник истины по протоколу.** DHT-структуры (строки 188–226, 635–645), ADNL-типы (строки 56–76), PublicKey-типы |

### Standalone DHT-демон

| Файл | Что содержит |
|------|-------------|
| `dht-server/dht-server.hpp` | Класс `DhtServer` (точка входа), структура `Config` (парсинг конфига, порты, ключи, control interface), default port=3278 |
| `dht-server/dht-server.cpp` | Полная инициализация: keyring → ADNL network → ADNL → DHT nodes → control interface, обработка control-команд, GC ключей |

### Вспомогательные утилиты (полезны для понимания)

| Файл | Что содержит |
|------|-------------|
| `dht/utils/dht-resolve.cpp` | Пример использования `get_value` — CLI-инструмент резолвинга |
| `dht/utils/dht-ping-servers.cpp` | Пример пинга DHT-узлов |

---

## Ключевые константы

- **k=10** — размер bucket, **a=3** — параллелизм lookup
- **Max TTL** = `now + 3600 + 60` секунд
- **Max value size** = 768 байт
- **Key name** max 127 байт, index max 15
- **256 buckets** (по одному на каждый бит XOR-расстояния)
- **`DhtKeyId`** = SHA256 от TL-сериализации `dht.key`
- **Подпись узла** = подпись TL-сериализации `dht_node` с пустой подписью; для network_id≠-1 в поле signature добавляется 4 байта network_id перед самой подписью
- Периодика: check каждые **1 сек**, republish каждые **~10 сек**, fill каждые **~10–20 сек**, save_to_db каждые **10 сек**
