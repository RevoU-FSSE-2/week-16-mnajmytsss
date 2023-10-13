
# Book API Documentation

This API provides endpoints for managing books. There are two clients (Client X and Client Y) with different access levels.

## Table of Contents

- API Endpoints
  - Create a New Book
  - Get All Books
  - PUT Book
  - DELETE Book
  - Register
  - Login
  - Logout
  - Refresh Token
  - Reset Password Request
  - Reset Password
- Client Role
  - Manage
  - Admin
  - User
- Client Permissions
    - Manager (GET)
    - Admin (GET) (POST, PUT, DELETE, "his own book only")
    - User (GET) (POST, PUT, DELETE, "his own book only")
- Middleware
  - CORS
  - Helmet
  - Morgan
  - Security XSS
  - Cookie Middleware
  - Body Parser

# Getting Started
## API Endpoints

### Create a New Book

- **URL:** `/api/v1/books`
- **Method:** `POST`
- **Request Body:**
  - `name` (string): The name of the book.
  - `author` (string): The author of the book.

#### Example

```json
{
  "name": "The Great Gatsby",
  "author": "F. Scott Fitzgerald"
}
```

### Response
```json
{
  "id": 1,
  "name": "The Great Gatsby",
  "author": "F. Scott Fitzgerald"
}
```

### Register

- **URL:** `/auth/register`
- **Method:** `POST`
### Login

- **URL:** `/auth/login`
- **Method:** `POST`
### Logout

- **URL:** `/auth/logout`
- **Method:** `POST`
### Refresh Token

- **URL:** `/auth/refresh-token`
- **Method:** `POST`
### Request to Reset Password

- **URL:** `/auth/reset-password`
- **Method:** `POST`

### Reset Password
### Get all Book

- **URL:** `/api/v1/books`
- **Method:** `GET`

### Update a Book

- **URL:** `/api/v1/books${id}`
- **Method:** `PUT`
- **New Books:**
    - `_id` (string): new book id
  - `name` (string): New update book name.
  - `author` (string): New update book author.

### Delete a Book

- **URL:** `/api/v1/books${id}`
- **Method:** `DELETE`

## Middleware
### CORS

Cross-Origin Resource Sharing (CORS) is configured to allow all origins for Client X and only permit GET and POST for Client Y.

### Helmet

Helmet is used to secure the application by setting various HTTP headers.

### Morgan

Morgan is an HTTP request logger middleware for logging requests.

### Security XSS

XSS protection is implemented both on the server and client side to prevent cross-site scripting attacks.

Feel free to customize this template according to your specific needs and add more details as required.


[Try me!!](https://lovely-ant-pea-coat.cyclic.app/)



