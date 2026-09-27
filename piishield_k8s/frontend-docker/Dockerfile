FROM nginx:alpine

COPY frontend/ /usr/share/nginx/html/

# Custom nginx config so the SPA can call the backend service by its
# Kubernetes DNS name (piishield-backend) rather than localhost — the
# frontend's index.html should read the API base URL from window.location
# or a build-time config; see k8s/frontend-configmap.yaml for the
# API_BASE_URL value injected as a runtime config.json.

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
