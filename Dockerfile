# ⚠️ TP10 : Dockerfile VOLONTAIREMENT mal configuré (à analyser avec trivy config puis corriger).
FROM node:14
WORKDIR /app
COPY . .
RUN npm install
EXPOSE 3000
CMD ["npm", "start"]
