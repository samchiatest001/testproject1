# testproject1

A simple Node.js API project with three subpaths and two endpoints per subpath.

## Requirements

- Node.js 18 or newer

## Run

```sh
npm start
```

The server runs at:

```txt
http://localhost:3000
```

## Endpoints

Token:

- `POST /getToken`
- `POST /token`

Users:

- `GET /users`
- `GET /users/status`

Products:

- `GET /products`
- `GET /products/status`

Orders:

- `GET /orders`
- `GET /orders/status`

## Authentication

Generate an access token:

```sh
curl -X POST http://localhost:3000/getToken \
  -H "Content-Type: application/json" \
  -H "secret: secret" \
  -d '{"username":"sam","role":"admin"}'
```

Response:

```json
{
  "accessToken": "..."
}
```

Use the token on every other endpoint:

```sh
curl http://localhost:3000/users \
  -H "Authorization: Bearer <accessToken>"
```

## Development

```sh
npm run dev
```
