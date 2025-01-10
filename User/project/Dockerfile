# Use the official Node.js lightweight image
FROM node:18-alpine

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

# Expose the app port
EXPOSE 80
EXPOSE 8082

# Start the Node.js application
CMD ["node", "backend/app.js"]
