# 1. Build stage
FROM node:18 AS builder

WORKDIR /app

COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build

# 2. Nginx stage (production web server)
FROM nginx:alpine

# Remove default content
RUN rm -rf /usr/share/nginx/html/*

# Copy built frontend
COPY --from=builder /app/dist /usr/share/nginx/html

# 🔴 THIS LINE WAS MISSING
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]