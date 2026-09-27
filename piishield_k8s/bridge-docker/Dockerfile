FROM node:18-slim

WORKDIR /app

COPY piishield-bridge/package.json ./
RUN npm install --production

COPY piishield-bridge/ ./

# connection-org1.json and wallet/ are mounted at runtime via ConfigMap/Secret
# (see k8s/bridge-deployment.yaml) rather than baked into the image, since
# they contain environment-specific Fabric network connection details and
# identity material that shouldn't be hardcoded into a container image.

EXPOSE 4000

CMD ["node", "app.js"]
