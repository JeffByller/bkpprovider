# MeuProvedor - Sistema de Monitoramento e Backup MikroTik

Aplicação web em FastAPI para monitoramento contínuo de conectividade (Ping/ICMP) com notificações em tempo real via Telegram e automação de backups dinâmicos para roteadores MikroTik.

## 🚀 Funcionalidades

- **Monitoramento ICMP Dinâmico**: Verificação contínua de latência e perda de pacotes.
- **Alertas de Perda e Recuperação (Histerese)**: Notificações inteligentes via Telegram para perdas de pacotes com margem de segurança contra oscilações de rede.
- **Backup Automatizado MikroTik**: Worker dinâmico em segundo plano que efetua backup SSH de roteadores MikroTik respeitando horários configurados via banco de dados.
- **Painel Administrativo**: Interface intuitiva para gerenciamento de alvos e configurações.

## 🛠️ Tecnologias Utilizadas

- **Backend**: Python 3 (FastAPI, asyncio, Paramiko)
- **Banco de Dados**: SQLite3
- **Frontend**: HTML5, CSS3, JavaScript Vanilla
- **Infraestrutura**: Docker & Docker Compose
