# Sistema de Gerenciamento de Documentos Administrativos 📄

Um dashboard administrativo completo desenvolvido em Flask para gerenciamento eficiente de documentos com suporte multi-tenant e internacionalização.

![Dashboard Preview](static/img/dashboard-preview.png)

## 🚀 Funcionalidades

- 📁 Gerenciamento completo de documentos
  - Upload/download de arquivos
  - Versionamento de documentos
  - Categorização inteligente
  - Busca avançada
- 👥 Sistema multi-tenant
  - Isolamento completo de dados
  - Gestão de departamentos
  - Controle de acesso granular
- 🌐 Internacionalização (i18n)
- 🎨 Temas claro/escuro com persistência
- 📱 Design responsivo
- 🔒 Autenticação e autorização

## 🛠️ Stack Tecnológica

- **Backend:**
  - Flask 3.0.0
  - SQLAlchemy ORM
  - Flask-Login
  - OAuth2

- **Frontend:**
  - JavaScript Vanilla
  - Feather Icons
  - CSS3 com variáveis para temas

- **Banco de Dados:**
  - PostgreSQL
  - psycopg2-binary

## 📋 Pré-requisitos

- Python 3.11+
- PostgreSQL
- pip (Gerenciador de pacotes Python)

## 🔧 Instalação

1. Clone o repositório:
```bash
git clone https://github.com/seu-usuario/admin-dashboard-system.git
cd admin-dashboard-system
```

2. Instale as dependências:
```bash
pip install -r requirements.txt
```

3. Configure as variáveis de ambiente:
```bash
cp .env.example .env
# Edite o arquivo .env com suas configurações
```

4. Inicialize o banco de dados:
```bash
flask db upgrade
```

5. Execute a aplicação:
```bash
flask run
```

## 🧪 Testando o Sistema

### Configuração Inicial

1. Acesse `http://localhost:5000`
2. Faça login com as credenciais padrão:
   - Usuário: `admin`
   - Senha: `admin123`

### Fluxo de Teste Básico

1. **Gerenciamento de Departamentos:**
   - Crie um novo departamento
   - Adicione categorias ao departamento

2. **Gestão de Documentos:**
   - Upload de documento
   - Categorização
   - Visualização
   - Download

3. **Configurações de Usuário:**
   - Alteração de tema (claro/escuro)
   - Configurações de perfil

## 📱 Screenshots

### Tela de Login
![Login](static/img/login-screen.png)

### Dashboard Principal
![Dashboard](static/img/main-dashboard.png)

### Gerenciamento de Documentos
![Documents](static/img/documents-management.png)

*Nota: As screenshots serão atualizadas conforme o desenvolvimento do projeto.*

## 👥 Contribuição

1. Faça o fork do projeto
2. Crie sua branch de feature (`git checkout -b feature/MinhaFeature`)
3. Commit suas mudanças (`git commit -m 'Adiciona nova feature'`)
4. Push para a branch (`git push origin feature/MinhaFeature`)
5. Abra um Pull Request

## 🔍 Testes

Execute os testes automatizados:
```bash
pytest
```

Para testes de cobertura:
```bash
pytest --cov=app tests/
```

## 📝 Licença

Este projeto está sob a licença MIT. Veja o arquivo [LICENSE](LICENSE) para mais detalhes.

## 🤝 Suporte

Para suporte, envie um email para support@example.com ou abra uma issue no GitHub.

## 📊 Status do Projeto

- ✅ Versão: 1.0.0
- 🚀 Última atualização: Janeiro 2025
- 📈 Status: Em desenvolvimento ativo

---

⌨️ com ❤️ por [Seu Nome](https://github.com/seu-usuario)
