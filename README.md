# CleanCity — Full Backend

This project converts the uploaded CleanCity civic issue tracker from browser-only storage to a real backend.

## Stack
- Node.js + Express
- SQLite (`better-sqlite3`)
- JWT authentication
- bcrypt password hashing
- Multer image upload
- Helmet/CORS
- Existing HTML/CSS/JavaScript frontend

## Features
- Register/login with name, email, phone and password
- Passwords are hashed; they are not stored as plain text
- JWT-based authenticated sessions
- SQLite user and report database
- Create civic reports with category, description, location, latitude/longitude and optional photo
- Public authenticated report list
- Upvotes stored on the server
- Admin-only status changes
- Status history table
- Profile update
- Uploaded images served from `/uploads`
- `/api/health` health-check endpoint

## Run

1. Install Node.js 18+.
2. Open a terminal in this folder.
3. Install packages:

   `npm install`

4. Copy `.env.example` to `.env` and set a strong JWT_SECRET.
5. Start:

   `npm start`

6. Open:

   `http://localhost:3000`

The SQLite database is created automatically at `data/cleancity.db`.

## Create an admin

After registering a normal account, run this SQL against the database:

`UPDATE users SET role='admin' WHERE email='your-email@example.com';`

Then log out and log back in.

## Important production notes
- Use HTTPS.
- Set a strong random JWT_SECRET in the environment.
- Add rate limiting, email verification, password reset, audit logging and CSRF/session hardening before public deployment.
- The map uses OpenStreetMap/Nominatim in the existing frontend; follow their usage policies for production traffic.