# 📡 MeuProvedor - Monitoramento ICMP & Backup Automático Mikrotik

Sistema leve e eficiente em Docker para monitoramento contínuo via ICMP (ping) com alertas instantâneos no Telegram e backup automático diário de roteadores Mikrotik (v6 / v7) via SSH.

---

## 🛠️ Tecnologias Utilizadas
- **Linguagem:** Python 3.11 (FastAPI, asyncio, paramiko, aiohttp)
- **Banco de Dados:** SQLite (persistido localmente em `./data/monitor.db`)
- **Proxy / SSL:** Nginx (Proxy reverso, SSL/TLS, autoassinados ou Let's Encrypt)
- **Containerização:** Docker & Docker Compose
- **Fuso Horário:** `America/Recife` (UTC-3)
- **Limites de Recursos:** 0.50 CPU | 128 MiB RAM por serviço

---

## 📋 Funcionalidades Principais

### 1. Monitoramento ICMP (Ping) & Alertas Telegram
- Dispara pings periódicos em segundo plano a cada 15 segundos para os IPs cadastrados.
- Caso um IP fique sem resposta por **1 minuto consecutivo** (4 pings falhos), dispara um alerta no grupo do Telegram configurado.
- Envia notificação automática no Telegram quando o host se **recupera (UP)**.

### 2. Backup Automático Mikrotik (v6 / v7)
- Conecta via SSH/SFTP nas RBs cadastradas.
- Gera o arquivo de exportação de configurações (`/export file=...`).
- Baixa o arquivo `.txt` (`.rsc`) para o servidor local (`./backups/`).
- **Retenção Inteligente:** Mantém apenas os **7 backups mais recentes** por dispositivo, excluindo automaticamente os mais antigos.
- **Agendamento:** Executa o backup automático diariamente **pontualmente às 17:00h** (horário de Recife).
- **Backup Manual:** Botão *"Backup Agora"* na interface para execução imediata.

### 3. Autenticação & Download Seguro
- Acesso à interface protegido por senha fixa de alta segurança.
- Para efetuar o download dos arquivos de backup `.txt`, o sistema exige a confirmação da senha de autorização.
- Botão de **Logout (Sair)** para encerramento de sessão.

---

## 🔐 Credenciais de Acesso
- **Senha Padrão:** `DtMzN51NkYuDe4`

---

## 🚀 Como Executar o Projeto

### Pré-requisitos
- Docker & Docker Compose instalados no Ubuntu / Linux.

### Subindo os Containers
```bash
docker compose up -d --build
```

Acesse no seu navegador:
- **`https://bkp.jeffgsan.com.br:4443`** (ou `https://SEU_IP:4443`)

---

## 📜 Passo a Passo para Gerar SSL Oficial (Let's Encrypt / Certbot)

Para substituir o certificado autoassinado pelo certificado oficial gratuito do **Let's Encrypt** usando o Certbot na VPS Ubuntu:

### 1. Instalar o Certbot no servidor Ubuntu:
```bash
sudo apt update
sudo apt install -y certbot
```

### 2. Gerar o certificado para o domínio `bkp.jeffgsan.com.br`:
*Certifique-se de que o domínio aponta para o IP da sua VPS e que as portas 80 e 443/4443 estejam abertas no firewall.*

```bash
sudo certbot certonly --standalone -d bkp.jeffgsan.com.br
```

Os certificados serão salvos no servidor em `/etc/letsencrypt/live/bkp.jeffgsan.com.br/`.

### 3. Ajustar o Nginx e o Docker Compose para usar o certificado oficial:

1. No arquivo `docker-compose.yml`, adicione o volume do Let's Encrypt no serviço `nginx`:
```yaml
    volumes:
      - /etc/localtime:/etc/localtime:ro
      - /etc/letsencrypt:/etc/letsencrypt:ro
```

2. No arquivo `nginx/default.conf`, altere a seção SSL de:
```nginx
ssl_certificate /etc/nginx/ssl/selfsigned.crt;
ssl_certificate_key /etc/nginx/ssl/selfsigned.key;
```

Para:
```nginx
ssl_certificate /etc/letsencrypt/live/bkp.jeffgsan.com.br/fullchain.pem;
ssl_certificate_key /etc/letsencrypt/live/bkp.jeffgsan.com.br/privkey.pem;
```

### 4. Recriar o container do Nginx:
```bash
sudo docker compose up -d --build nginx
```


---

## 📁 Estrutura de Arquivos Persistidos
Ao clonar ou mover o projeto para outro servidor, os dados cadastrados e os backups permanecem intactos nas seguintes pastas:
- `./data/` -> Banco de dados SQLite (`monitor.db`)
- `./backups/` -> Arquivos de backup das RBs Mikrotik
