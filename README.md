
# Book API Documentation

This API provides endpoints for managing books. There are two clients (Client X and Client Y) with different access levels.

![Local Image](./assets/3.png)

![Local Image](./assets/2.png)

## Table of Contents

- API Endpoints
  - Create a New Book
  - Get All Books
  - PUT Book
  - DELETE Book
- Client Permissions
    - Origin (GET, POST, PUT, DELETE)
    - Partner Origin (GET, POST) 
- Middleware
  - CORS
  - Helmet
  - Morgan
  - Security XSS

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

# Client Permissions
- There is 3 api in this site that allowed to acces from this site
    - **Najmy's Api** Can perform all methods (GET, POST, UPDATE, DELETE).
    - **Deffi's Api** Can only perform GET and POST methods.
    - **Avicena's Api** Can only perform GET and POST methods.

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


![Local Image](./assets/1.png)


[Try me!!](https://week-15-mnajmytsss.vercel.app/)



