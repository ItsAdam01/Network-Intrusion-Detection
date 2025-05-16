# Stage 1: Build React app
# Using Node 18 alpine for a lightweight, modern build env
FROM node:18-alpine AS build
WORKDIR /app

# Add build arguments for backend URLs
# These must start with REACT_APP_ for the React build process to include them
ARG REACT_APP_NIDS_URL
ARG REACT_APP_WAF_URL
ENV REACT_APP_NIDS_URL=$REACT_APP_NIDS_URL
ENV REACT_APP_WAF_URL=$REACT_APP_WAF_URL

COPY package*.json ./
RUN npm install --silent

COPY . .
RUN npm run build

# Stage 2: Serve using Nginx
FROM nginx:stable-alpine
COPY --from=build /app/build /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 3000
CMD ["nginx", "-g", "daemon off;"]
