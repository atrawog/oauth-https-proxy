FROM node:22.12-alpine AS builder

# Copy all files directly since we're in the mcp-everything directory
COPY . /app

WORKDIR /app

RUN npm install
RUN npm run build

FROM node:22-alpine AS release

WORKDIR /app

COPY --from=builder /app/dist /app/dist
COPY --from=builder /app/package.json /app/package.json
COPY --from=builder /app/node_modules /app/node_modules

ENV NODE_ENV=production
ENV PORT=3000

# Expose port 3000 for the streamableHttp server
EXPOSE 3000

# Run the streamableHttp server
CMD ["node", "dist/streamableHttp.js"]