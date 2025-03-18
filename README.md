# BootDevCourse

This project was primarily to help me try out Go/Postgres and is loosely based on an [online guide](https://www.boot.dev/courses/learn-http-servers-golang).
It's a very simple API that allows users to create and manage chirps (short messages). This project includes authentication, user management, and a "premium" Chirpy Red membership feature.

## Features
- **User Management**: Register, login, update profile.
- **Authentication**: Secure JWT-based authentication.
- **Chirps**: Create, retrieve, and filter chirps.
- **Polka Webhook**: Handle premium membership upgrades securely. (Not an actual webhook to any service)
- **Sorting & Filtering**: Fetch chirps by author and sort by date.

## Technologies Used
- **Go**: Backend API implementation.
- **PostgreSQL**: Database for user and chirp storage.
- **sqlc**: SQL query generation.
- **bcrypt**: Secure password hashing.
- **JWT**: Authentication tokens.
- **Goose**: Database migrations.

## Setup Instructions (Database is private)

### Prerequisites
- Go installed (>=1.18)
- PostgreSQL installed
- `sqlc`, `goose` installed

### Installation
1. **Clone the repository:**
   ```sh
   git clone https://github.com/your-username/chirpy-api.git
   cd chirpy-api
   ```

2. **Set up environment variables:**
   Create a `.env` file with the following variables:
   ```ini
   DATABASE_URL=postgres://user:password@localhost:5432/chirpy
   JWT_SECRET=your_jwt_secret
   POLKA_KEY=f271c81ff7084ee5b99a5091b42d486e
   ```

3. **Run database migrations:**
   ```sh
   goose up
   ```

4. **Generate database queries:**
   ```sh
   sqlc generate
   ```

5. **Run the server:**
   ```sh
   go run main.go
   ```

## API Endpoints

### Authentication & Admin
- `POST /api/users` - Register a new user
- `POST /api/login` - Login and receive JWT
- `PUT /api/users` - Update user email/password (requires authentication)
- `POST /admin/reset` - Clear/Reset entire db
- `POST /api/revoke` - Revoke a refresh token
- `POST /api/refresh` - Get a refresh token
- `GET /admin/metrics` - How many times server has been visited
- `GET /api/healthz` - Server status

### Chirps
- `POST /api/chirps` - Create a new chirp (requires authentication)
- `GET /api/chirps` - Retrieve chirps (supports `author_id` and `sort` query params)

### Chirpy Red Membership
- `POST /api/polka/webhooks` - Handle premium membership upgrades (validates Polka API key)

## Query Parameters for Chirps
- `author_id`: Filter chirps by user ID
- `sort`: Sort by `created_at` (`asc` or `desc`, default is `asc`)

## Example Requests

### Register User
```sh
curl -X POST http://localhost:8080/api/users -d '{"email": "test@example.com", "password": "password123"}' -H "Content-Type: application/json"
```

### Create Chirp (Authenticated)
```sh
curl -X POST http://localhost:8080/api/chirps -d '{"body": "Hello world!"}' -H "Authorization: Bearer YOUR_JWT_TOKEN" -H "Content-Type: application/json"
```

### Retrieve Chirps Sorted Descending
```sh
curl -X GET "http://localhost:8080/api/chirps?sort=desc"
```

## License
This project is licensed under the MIT License.

