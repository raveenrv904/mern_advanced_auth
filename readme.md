# MERN Advanced Authentication

This project demonstrates a full authentication system built with the MERN (MongoDB, Express, React, Node.js) stack. It includes features like email sign-up, password protection, and a 6-digit OTP verification for users.

## Features

- **Sign-up process**: Users can sign up using their email, name, and password.
- **Email verification**: After sign-up, users receive a 6-digit OTP via email for verification before accessing the app.
- **Mailtrap integration**: Mails are sent using the Mailtrap API to simulate email delivery during development.
- **Home page access**: Only verified users can proceed to the home page.

## Tech Stack

- **Frontend**: React
- **Backend**: Node.js, Express.js
- **Database**: MongoDB
- **Email Service**: Mailtrap API

## Setup Instructions

1. Clone the repository:

```bash {"id":"01J7YZ669FZHCP8X1153WPXJY1"}
git clone https://github.com/raveenrv904/mern_advanced_auth.git
cd mern_advanced_auth
```

2. Install dependencies:

```bash {"id":"01J7YZ669FZHCP8X1155GJH7EW"}
npm install
```

3. Set up environment variables by creating a .env file and adding:

```bash {"id":"01J7YZ669FZHCP8X11570ZHZ9C"}
PORT=port
MONGO_URI=mongodb_url
JWT_SECRET=jwt_secret
NODE_ENV=production
MAILTRAP_TOKEN=mailtrap_token
CLIENT_URL=http://localhost:5173
```

4. Run the server

```bash {"id":"01J7YZ669FZHCP8X1158GBYCT0"}
npm run dev
```

5. Navigate to http://localhost:3000 to view the application.

## Future Improvements

- Password reset functionality.
- Enhanced security features (e.g., password strength validation)

## License

This project is licensed under the MIT License.
