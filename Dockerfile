# Use the official Node.js Alpine image as the base image for the build stage
FROM node:alpine AS build

# Set the working directory
WORKDIR /app

# Copy package.json and package-lock.json for dependency caching
COPY package.json package-lock.json ./

# Install dependencies
RUN npm install --only=production

# Copy the rest of the application code
COPY . .

# Build the application (if applicable, e.g., for TypeScript or other build steps)
# RUN npm run build

# Use a smaller image for the production stage
FROM node:alpine AS production

# Set the working directory
WORKDIR /app

# Copy only the necessary files from the build stage
COPY --from=build /app .

# Set environment variable for production
ENV NODE_ENV=production

# Create a non-root user and switch to it
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

# Expose the application port
EXPOSE 5000

# Health check to ensure the application is running
HEALTHCHECK CMD curl --fail http://localhost:5000/ || exit 1

# Command to run the application
CMD ["node", "index.js"]