# PIIShield on Kubernetes — Scope & Setup

## What this covers

Kubernetes manifests that containerize and orchestrate PIIShield's
**application layer**: the FastAPI backend, the Fabric bridge service,
and the frontend. Together they demonstrate the report's objective of
"a scalable and user-friendly system... deployed using containerization
technologies like Docker and orchestration platforms such as Kubernetes."

## What this does NOT cover (be upfront about this in your viva)

**Hyperledger Fabric itself is not deployed on Kubernetes here.** The
Fabric network (orderer, peers, CAs) continues to run via Docker Compose
/ `network.sh` on the host, exactly as it does now. Running Fabric on
Kubernetes properly requires the Hyperledger Fabric Operator, per-peer
StatefulSets with persistent volumes, and considerably more setup — a
legitimately separate, larger effort. Bundling that in now would risk
breaking your already-working, already-tested Fabric deployment with very
little time to recover before a viva.

**This is a defensible, honest scope**: many real systems keep a
blockchain network as fixed backing infrastructure while orchestrating
the application layer with Kubernetes around it.

## Files

```
k8s/
  00-namespace.yaml           — isolated "piishield" namespace
  01-configmap.yaml           — non-secret config (URLs, ports)
  02-secret-template.yaml     — TEMPLATE for Fabric wallet identity (do not apply as-is)
  03-bridge-deployment.yaml   — Node.js bridge Deployment + Service
  04-backend-deployment.yaml  — FastAPI backend Deployment + Service + PVC
  05-frontend-deployment.yaml — nginx-served frontend Deployment + Service
  06-ingress.yaml             — external routing (/api -> backend, / -> frontend)
  07-hpa.yaml                 — autoscaling for the backend (2-6 replicas on CPU)

bridge-docker/Dockerfile      — containerizes piishield-bridge
frontend-docker/Dockerfile    — containerizes the static frontend via nginx
```

Your existing `backend/Dockerfile` (already in your project) is reused
as-is for the backend image.

## If you want to actually test this locally (optional, budget ~1-2 hours)

This requires a local Kubernetes cluster. The simplest option inside
WSL2/Ubuntu is `minikube`.

### 1. Install minikube and kubectl

```bash
curl -Lo minikube https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
sudo install minikube /usr/local/bin/
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo install kubectl /usr/local/bin/
```

### 2. Start minikube

```bash
minikube start --driver=docker
```

### 3. Build the images inside minikube's Docker daemon

```bash
eval $(minikube docker-env)
docker build -t piishield-backend:latest ~/piishield_clean/backend/
docker build -t piishield-bridge:latest -f bridge-docker/Dockerfile ~/
docker build -t piishield-frontend:latest -f frontend-docker/Dockerfile ~/piishield_clean/
```

### 4. Create the real Fabric wallet secret (replace the template)

```bash
kubectl create namespace piishield
kubectl create secret generic piishield-fabric-wallet \
  --namespace piishield \
  --from-file=connection-org1.json=~/piishield-bridge/connection-org1.json \
  --from-file=admin.id=~/piishield-bridge/wallet/admin.id \
  --from-file=appUser.id=~/piishield-bridge/wallet/appUser.id
```

### 5. Apply the manifests (skip 00-namespace.yaml and 02-secret-template.yaml, already handled above)

```bash
kubectl apply -f k8s/01-configmap.yaml
kubectl apply -f k8s/03-bridge-deployment.yaml
kubectl apply -f k8s/04-backend-deployment.yaml
kubectl apply -f k8s/05-frontend-deployment.yaml
kubectl apply -f k8s/07-hpa.yaml
```

### 6. Check status

```bash
kubectl get pods -n piishield
kubectl get svc -n piishield
```

### 7. Access it

```bash
minikube service piishield-frontend -n piishield --url
```

**Known limitation to expect**: since Fabric runs on the host (outside
minikube's Docker network), the bridge pod needs to reach it via
`host.docker.internal` or minikube's host-gateway IP
(`minikube ssh -- "cat /etc/resolv.conf"` to find it) rather than
`localhost` — this networking bridge between minikube and host Docker
is the most likely thing to need troubleshooting if you actually attempt
this, similar to the Docker/WSL networking issues you already solved
for the Fabric setup itself.

## What to say in your viva

> "I containerized the application layer — backend, Fabric bridge, and
> frontend — as separate Kubernetes Deployments with health checks,
> resource limits, and horizontal autoscaling on the backend. The
> Hyperledger Fabric network itself runs as fixed backing infrastructure
> via Docker Compose, since deploying Fabric natively on Kubernetes
> requires the Fabric Operator and considerably more infrastructure — a
> reasonable scoping decision given the project timeline, and a common
> pattern in real deployments where blockchain infrastructure is
> provisioned separately from the application layer that consumes it."

This is an honest, technically literate answer that shows you understand
the tradeoff rather than having glossed over it.
