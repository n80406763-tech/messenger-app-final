# Family Messenger (клиент + сервер)

Простой мессенджер для семьи: регистрация, вход, общий чат, realtime-сообщения через SSE.

## Что внутри

- Node.js (только встроенные модули, без внешних зависимостей)
- HTTP API для регистрации, входа, выхода, онлайн-статуса и сообщений
- SSE-канал для realtime-доставки сообщений и presence-обновлений
- Хранение данных в `messenger.json`
- Пароли хэшируются через `pbkdf2` из `crypto`
- Базовые лимиты на попытки входа и частоту отправки сообщений
- Автоматическое восстановление сессии на клиенте (через `localStorage`)
- Кнопка подгрузки старых сообщений (пагинация через `before_id`)
- HTTP API для регистрации, входа, выхода, отправки сообщений и проверки сессии
- SSE-канал для realtime-доставки сообщений
- Хранение данных в `messenger.json`
- Пароли хэшируются через `pbkdf2` из `crypto`
- Базовые лимиты на попытки входа и частоту отправки сообщений

## Быстрый старт

```bash
node server.js
```

Открой: `http://localhost:3000`

## API

- `GET /api/health` — статус сервера
- `POST /api/register` — регистрация `{ username, password }`
- `POST /api/login` — вход `{ username, password }`
- `POST /api/logout` — выход (Bearer token)
- `GET /api/me` — текущий пользователь (Bearer token)
- `GET /api/online` — кто сейчас онлайн (Bearer token)
- `GET /api/messages?limit=40&before_id=123` — история (по умолчанию 100, максимум 200)
- `POST /api/messages` — отправка сообщения `{ text }` (Bearer token)
- `GET /api/events` — SSE-поток новых сообщений и presence (Bearer token)
- `GET /api/messages` — последние 100 сообщений (Bearer token)
- `POST /api/messages` — отправка сообщения `{ text }` (Bearer token)
- `GET /api/events` — SSE-поток новых сообщений (Bearer token)

## Деплой на VPS (1 CPU / 1 GB RAM)

1. Установи Node.js 18+
2. Склонируй проект
3. Запусти `node server.js`
4. Настрой `nginx` как reverse proxy
5. Включи HTTPS через Let's Encrypt
6. Настрой автозапуск через `systemd`

## Безопасность и эксплуатация

- Делай бэкап файла `messenger.json` (например, ежедневно).
- Для продакшена добавь fail2ban, ротацию логов и вынеси секреты/настройки в env.
- Для статических файлов включены заголовки CSP, X-Frame-Options и X-Content-Type-Options.
- Для продакшена стоит добавить fail2ban, ротацию логов и вынести секреты/настройки в env.
- Это семейный MVP: для публичного сервиса нужна полноценная модель сессий, аудит и более строгие политики безопасности.
# messenger-app-final
