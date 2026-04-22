FROM node:latest

ENV DATABASE_URL=postgresql://admin:hunter2abc@prod-db:5432/app
ENV AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI_K7MDENG_bPxRfiCYEXAMPLEKEY

ADD https://example.com/install.sh /tmp/install.sh
RUN curl https://get.pnpm.io/install.sh | bash

COPY . .

EXPOSE 22
EXPOSE 5432

CMD ["node", "server.js"]
