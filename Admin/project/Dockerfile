# Use the official Node.js lightweight image
FROM node:18-alpine

# Install Nginx
RUN apk update && apk add --no-cache nginx curl
RUN apk add --no-cache mongodb-tools


# Set the working directory inside the container
WORKDIR /usr/src/app

# Copy dependency definitions
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy application source code
COPY backend ./backend
COPY frontend ./frontend

# Expose the ports
EXPOSE 80
EXPOSE 8080

# Start Nginx and the app
CMD ["sh", "-c", "nginx && node backend/app.js"]
