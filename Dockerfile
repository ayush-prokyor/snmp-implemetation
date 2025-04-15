# Stage 1: Build the binary using pkg
FROM node:16-alpine AS builder
WORKDIR /usr/src/app

# Copy package.json and package-lock.json first to improve caching
COPY package*.json ./
RUN npm install

# Copy the rest of the source code
COPY . .

# Install pkg globally and build the binary 
RUN npm install -g pkg && pkg app.js --targets node16-alpine --output app --assets "public/**/*"

# Stage 2: Create the runtime image with only the binary
FROM node:16-alpine
WORKDIR /usr/src/app
COPY --from=builder /usr/src/app/app .

EXPOSE 3000
EXPOSE 161
EXPOSE 16200

CMD ["./app"]
