<div align="center">

# 🛡️ SecureScan

### Scanner Automatizado de Vulnerabilidades Web (OWASP Top 10) com Interpretação e Remediação via Inteligência Artificial Generativa

[![Python Version](https://img.shields.io/badge/Python-3.11%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![React Version](https://img.shields.io/badge/React-18-61dafb?logo=react&logoColor=black)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0-3178c6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![OWASP Top 10](https://img.shields.io/badge/OWASP-Top%2010%202021-e02424)](https://owasp.org/Top10/)
[![CVSS v3.1](https://img.shields.io/badge/CVSS-v3.1%20Scoring-orange)](https://www.first.org/cvss/)
[![Google Gemini](https://img.shields.io/badge/AI-Google%20Gemini-8e75ff?logo=google&logoColor=white)](https://aistudio.google.com/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

<p align="center">
  <b>Uma solução híbrida que une auditoria heurística dinâmica ativa (DAST) à capacidade semântica de Large Language Models (LLMs) para fechar o abismo entre a descoberta de falhas e a entrega de código corretivo.</b>
</p>

[Visão Geral](#-visão-geral) •
[Funcionalidades](#-funcionalidades) •
[Arquitetura](#-arquitetura) •
[Módulos OWASP](#-módulos-de-auditoria) •
[Instalação](#-instalação-e-execução) •
[Demonstração da IA](#-exemplo-de-remediação-com-ia) •
[Publicação Acadêmica](#-publicação-acadêmica--tcc)

---

</div>

## 📌 Visão Geral

O **SecureScan** é uma ferramenta de cibersegurança defensiva desenvolvida como Trabalho de Conclusão de Curso (TCC). O projeto resolve uma das maiores dores da segurança de software moderna: **a sobrecarga de alertas e o abismo de remediação**.

Enquanto scanners convencionais (DAST) emitem relatórios prolixos e mensagens frias como *"SQL Injection detectado no parâmetro id"*, o **SecureScan** orquestra testes ativos contra a aplicação, captura as evidências reais do ataque e utiliza **Modelos de Linguagem de Grande Escala (Google Gemini)** para entregar em menos de 3 segundos:
1. **Causa Raiz:** Explicação didática em linguagem natural do porquê o código falhou;
2. **Impacto no Negócio:** Avaliação de risco nas dimensões de Confidencialidade, Integridade e Disponibilidade;
3. **Plano de Remediação Prescritivo:** Orientações diretas de arquitetura defensiva;
4. **Patches de Código Seguro:** Código funcional pronto para copiar e colar na linguagem do alvo (ex.: *Prepared Statements* com PDO em PHP).

---

## ✨ Funcionalidades

- **Varredura Ativa Heurística (DAST):** Disparo parametrizado de *payloads* em tempo real com controle de concorrência e sessão HTTP autenticada (suporte a cookies e tokens anti-CSRF).
- **Cobertura das Principais Classes do OWASP Top 10:** Injeções de código (SQLi, XSS, Command Injection), quebras de autenticação/força bruta e desconfigurações de segurança.
- **Auditoria Dedicada para WordPress:** Enumeração de versões legadas, usuários expostos via REST API (`/wp-json/wp/v2/users`), interface `/xmlrpc.php` ativa e resiliência da busca nativa (`$wpdb`).
- **Métricas Matemáticas CVSS v3.1:** Cálculo objetivo de pontuação de severidade (0.0 a 10.0) para priorização correta de chamados e eliminação de falsos positivos (*status SAFE*).
- **Camada de IA com Saídas Estruturadas (*Structured Outputs*):** Consultas ao Google Gemini orientadas por esquemas JSON rigorosos, impedindo alucinações e padronizando as análises.
- **Interface Web Moderna (*Dark Slate Cybersecurity*):** Desenvolvida em React e TypeScript, oferecendo painéis analíticos com gráficos de distribuição de severidade, console de evidências em tempo real e visualizador de relatórios executivos.
- **Múltiplos Formatos de Exportação:** Geração de relatórios executivos e técnicos em **PDF**, **Markdown (.md)**, **HTML** e **JSON**.
- **Modo CLI & Modo Web:** Suporte a execução automatizada via linha de comando (`main.py`) ou painel interativo completo (`app.py`).

---

## 🏛️ Arquitetura

O SecureScan opera sob o paradigma cliente-servidor desacoplado, com pipeline de auditoria em 6 etapas:

```
[ Usuário / Analista ]
        │
        ▼ (1. Configuração do Alvo e Seleção de Módulos)
┌────────────────────────────────────────────────────────┐
│             Interface Web (React / TypeScript)         │
└────────────────────────────────────────────────────────┘
        │
        ▼ (2. Requisições REST & Gestão de Sessão)
┌────────────────────────────────────────────────────────┐
│             Servidor Backend (Python 3.11)             │
└────────────────────────────────────────────────────────┘
        │
        ├────────────────────────────────┐
        ▼ (3. Disparo Heurístico Ativo)  ▼ (Alvos em Laboratório)
┌───────────────────────────────┐ ┌──────────────────────┐
│     Módulos de Ataque DAST    │ │  • DVWA (Low/Med/High│
│  • SQLi (Error & Boolean)     │ │  • WordPress CMS     │
│  • Reflected XSS              │ └──────────────────────┘
│  • OS Command Injection       │
│  • Força Bruta com Anti-CSRF  │
│  • Cabeçalhos & Desconfiguração│
└───────────────────────────────┘
        │
        ▼ (4. Validação de Respostas, Filtro de Falsos Positivos & CVSS v3.1)
┌────────────────────────────────────────────────────────┐
│           Consolidação Heurística de Evidências        │
└────────────────────────────────────────────────────────┘
        │
        ▼ (5. Structured Prompt Engineering em JSON)
┌────────────────────────────────────────────────────────┐
│        Camada de IA Generativa (Google Gemini API)     │
│  • Causa Raiz • Risco Real • Patches de Código Seguro  │
└────────────────────────────────────────────────────────┘
        │
        ▼ (6. Renderização & Exportação)
┌────────────────────────────────────────────────────────┐
│     Dashboard, Relatório Executivo e Exportação PDF    │
└────────────────────────────────────────────────────────┘
```

---

## 🔍 Módulos de Auditoria

| Categoria OWASP | Módulo Técnico | Vetores de Teste / Cargas | Validação e Evidência Heurística | Severidade CVSS |
| :--- | :--- | :--- | :--- | :---: |
| **A03:2021** | **SQL Injection** | `' OR '1'='1`, `1 OR 1=1`, `1' OR '1'='1' #` | Assinaturas de erros de SGBD (MySQL/PostgreSQL) e vazamento anômalo de tabelas via tautologia booleana. Contorna filtros nos níveis Low, Medium e High do DVWA. | **Alta (8.8)** |
| **A03:2021** | **Reflected XSS** | `<script>alert(1)</script>`, `<img src=x onerror=...>`, `<svg>` | Reflexão literal de tags HTML e manipuladores de eventos JavaScript no DOM sem codificação de caracteres especiais. | **Média (6.1)** |
| **A03:2021** | **Command Injection** | Delimitadores de shell (`;`, `&&`, `\|`, `\|echo`) | Concatenação de comandos de sistema operacional (`whoami`, `id`, `ping`) com extração de saída do servidor web (*bypass* do nível High). | **Crítica (9.8)** |
| **A07:2021** | **Força Bruta** | Dicionários curados com raspagem dinâmica de tokens | Extração dinâmica do token anti-CSRF (`user_token`), identificação de redirecionamento 302 e concessão de credenciais válidas. | **Alta (8.1)** |
| **A05:2021** | **Security Headers** | Inspeção de cabeçalhos de resposta HTTP | Identificação de ausência de políticas defensivas: *Content-Security-Policy* (CSP), *X-Frame-Options*, *HSTS* e *X-Content-Type-Options*. | **Média (5.3)** |
| **A05:2021** | **Auditoria WordPress** | REST API, XML-RPC, `readme.html` e busca | Exposição de logins de autores em `/wp-json/wp/v2/users`, serviço `/xmlrpc.php` ativo, versão do core exposta e validação segura de consultas nativas (`$wpdb`). | **Média (5.3) / Seguro (0.0)** |

---

## 🤖 Exemplo de Remediação com IA

Quando o SecureScan detecta uma injeção de SQL no ambiente de testes, a IA não emite um aviso genérico; ela entrega a solução diretamente contextualizada no código do alvo:

```php
// ❌ CÓDIGO VULNERÁVEL IDENTIFICADO NO ALVO:
$query = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
$result = mysqli_query($GLOBALS["___mysqli_ston"], $query);

// ✅ CÓDIGO CORRETIVO GERADO PELO SECURESCAN (Prepared Statements com PDO):
$stmt = $pdo->prepare('SELECT first_name, last_name FROM users WHERE user_id = :id');
$stmt->execute(['id' => $id]);
$user = $stmt->fetch();
```

> **Explicação da Causa Raiz pela IA:** *"O parâmetro `id` é concatenado diretamente na consulta SQL sem sanitização ou parametrização. Isso permite que um atacante adultere a lógica booleana da cláusula WHERE e extraia registros arbitrários do banco de dados relacional."*

---

## 🚀 Instalação e Execução

### Pré-requisitos
- **Python 3.10+** instalado
- **Node.js 18+** e npm instalados
- Uma chave de API para a camada de IA (Google Gemini ou OpenRouter)
- Alvo didático para testes (ex.: container Docker com [DVWA](https://github.com/digininja/DVWA) ou instância local do WordPress)

### 1. Clonar o Repositório
```bash
git clone https://github.com/NicolasPcastr0/TCC-Py_vulScanner.git
cd TCC-Py_vulScanner
```

### 2. Configurar o Backend (Python)
Instale as dependências do Python:
```bash
pip install -r requirements.txt
```

Crie o arquivo de variáveis de ambiente a partir do exemplo:
```bash
cp .env.example .env
```
Abra o `.env` e insira sua chave da API da Inteligência Artificial:
```env
# Opção 1: Chave da API do Google Gemini (Recomendado):
GEMINI_API_KEY=sua_chave_aqui

# Opção 2: Chave do OpenRouter (Llama 3.3, DeepSeek, etc.):
OPENROUTER_API_KEY=sua_chave_aqui
```

### 3. Configurar e Compilar o Frontend (React)
Acesse a pasta do frontend e instale os pacotes:
```bash
cd frontend
npm install
npm run build
cd ..
```

### 4. Executar o SecureScan

#### Modo Web Interativo (Recomendado)
Inicia o servidor completo que serve a interface React e a API de varredura:
```bash
python app.py
```
Acesse no seu navegador: **[http://localhost:5000](http://localhost:5000)**

#### Modo Linha de Comando (CLI)
Para executar a auditoria diretamente no terminal e gerar relatórios em arquivo:
```bash
python main.py
```
*(Os relatórios gerados serão salvos automaticamente na pasta `reports/` nos formatos `.md`, `.html` e `.json`)*.

---

## 🧪 Ambiente de Testes Didático (DVWA / Docker)

Para testar o scanner em um ambiente seguro e controlado, você pode subir o DVWA via Docker:

```bash
docker run --rm -it -p 80:80 vulnerables/web-dvwa
```
- Acesse `http://localhost/setup.php` para inicializar a base de dados do DVWA.
- Credenciais padrão: Usuário `admin` | Senha `password`.
- No SecureScan, aponte a URL alvo para `http://localhost` e selecione o nível de segurança desejado (*Low*, *Medium* ou *High*).

---

## 📂 Estrutura de Diretórios

```
TCC-Py_vulScanner/
├── frontend/                   # Interface Web em React + TypeScript + Vite
│   ├── src/
│   │   ├── components/         # Componentes (Dashboard, Findings, Relatório IA, etc.)
│   │   ├── index.css           # Estilos e Design Tokens (Dark Slate Theme)
│   │   └── App.tsx             # Gerenciamento de rotas e estado central
│   └── package.json
├── scanner/                    # Núcleo da Ferramenta de Varredura
│   ├── ai/                     # Camada de IA (prompts, schemas e integração Gemini)
│   ├── core/                   # Orquestrador principal, Findings e cálculo CVSS
│   ├── modules/                # Módulos ativos do OWASP Top 10 (SQLi, XSS, Cmd, etc.)
│   ├── reports/                # Exportadores de relatório (Markdown, HTML, JSON)
│   └── utils/                  # Utilitários de sessão DVWA e auditoria WordPress
├── reports/                    # Diretório de relatórios gerados por auditorias CLI
├── app.py                      # Servidor HTTP / API REST unificada (Porta 5000)
├── main.py                     # Ponto de entrada para execução em linha de comando (CLI)
├── requirements.txt            # Dependências Python
└── README.md                   # Documentação do projeto
```

---

## 🎓 Publicação Acadêmica / TCC

Este projeto é fruto do Trabalho de Conclusão de Curso (TCC) em Ciência da Computação / Engenharia de Software submetido à **Revista Brasileira de Iniciação Científica (RBIC - IFSP)**:

> **CASTRO, Nicolas Pereira de; SANTOS, Tiago.** *SecureScan: Desenvolvimento de um Scanner Automatizado de Vulnerabilidades Web baseado no OWASP Top 10 com Interpretação e Remediação via Inteligência Artificial Generativa*. Revista Brasileira de Iniciação Científica (RBIC), v. 13, 2026.

```bibtex
@article{castro2026securescan,
  title={SecureScan: Desenvolvimento de um Scanner Automatizado de Vulnerabilidades Web baseado no OWASP Top 10 com Interpretação e Remediação via Inteligência Artificial Generativa},
  author={Castro, Nicolas Pereira de and Santos, Tiago},
  journal={Revista Brasileira de Iniciação Científica (RBIC)},
  volume={13},
  year={2026}
}
```

---

## ⚖️ Aviso Legal (*Disclaimer*)

Esta ferramenta foi desenvolvida estritamente para **fins acadêmicos, educativos e defensivos**. A execução de testes de penetração ou varreduras de vulnerabilidades contra sistemas de terceiros sem autorização prévia e formal constitui crime cibernético perante legislações locais e internacionais (incluindo a Lei nº 12.737/2012 - Lei Carolina Dieckmann no Brasil). Os autores não se responsabilizam pelo uso indevido deste software.

---

<div align="center">
  Desenvolvido por <b>Nicolas Pereira de Castro</b> com orientação de <b>Tiago</b> • 2026
</div>
