-- Tabela de usuários
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user'
);

-- Tabela de agendamentos
CREATE TABLE IF NOT EXISTS agendamentos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nome TEXT NOT NULL,
    horario TEXT NOT NULL,
    servico TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabela de serviços oferecidos
CREATE TABLE IF NOT EXISTS servicos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nome TEXT NOT NULL,
    descricao TEXT,
    duracao INTEGER NOT NULL, -- duração em minutos
    preco DECIMAL(10, 2) NOT NULL,
    disponivel BOOLEAN NOT NULL DEFAULT 1
);

-- Inserir alguns serviços de exemplo
INSERT OR IGNORE INTO servicos (nome, descricao, duracao, preco) VALUES 
('Corte de Cabelo', 'Corte tradicional masculino ou feminino', 30, 50.00),
('Manicure', 'Cuidados com as unhas das mãos', 45, 35.00),
('Pedicure', 'Cuidados com as unhas dos pés', 45, 40.00),
('Design de Sobrancelhas', 'Modelagem e definição das sobrancelhas', 20, 25.00);