// /server.js

require('dotenv').config();
const express = require('express');
const validator = require('express-openapi-validator');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const db = require('pg');

const server = express();
const port = process.env.EXPRESS_PORT;
const pool = new db.Pool({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    database: process.env.DB_DATABASE,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD
});

const rolesMiddleware = (roles) => (request, response, next) => {
    if (!roles.includes(request.jwtpayload.role)) {
        response.status(403).json();
        return;
    }
    next();
};

server.use(express.json());

server.use(
    validator.middleware({
        apiSpec: 'api.yaml',
        validateRequests: true,
        validateResponses: false,
        validateSecurity: {
            handlers: {
                bearer: (request, scopes, schema) => {
                    request.jwtpayload = jwt.verify(request.headers.authorization.replace('Bearer ', ''), process.env.JWT_SECRET);
                    return(true);
                }
            }
        }
    })
);

// Rota POST para autenticação de funcionário. Valida o usuário e a senha criptografada, gerando um token JWT de acesso em caso de sucesso.
server.post('/funcionario/autenticacao', async (request, response) => {
    try {
        const result = await pool.query('SELECT * FROM funcionario WHERE codigo = $1', [ request.body.usuario ]);
        if (result.rows.length == 0) {
            response.status(401).json();
            return;
        }
        const hash = result.rows[0].senha;
        if (!bcrypt.compareSync(request.body.senha, hash)) {
            response.status(401).json();
            return;
        }
        const token = jwt.sign({ sub: result.rows[0].codigo, role: result.rows[0].papel }, process.env.JWT_SECRET, { expiresIn: '5m' });
        response.status(200).json({ token: token });
        } catch (error) {
        console.log(error.stack);
        response.status(500).json(error.message);
    }
});

// Rota POST para renovação/validação do token JWT enviado no cabeçalho de autorização.
server.post('/funcionario/autenticacao/renovacao', (request, response) => {
    let token = request.headers.authorization;
    try {
        if (token.startsWith('Bearer ')) {
            token = token.replace('Bearer ', '');
        } else {
            token = '';
        }
        const payload = jwt.verify(token, process.env.JWT_SECRET);
        console.log(payload);
        response.status(200).json();
    } catch (error) {
        console.log(error.stack);
        response.status(401).json(error.message);
    }
});

// Rota GET para listar funcionários com paginação e filtro opcional por nome usando ILIKE, restrita aos papéis 1 e 3.
server.get('/funcionario', rolesMiddleware([ 1, 3 ]), async (request, response) => {
    try {
        let nome = request.query.nome;
        if (nome === undefined)
        {    nome = '';
        }
        nome = '%'+nome.replaceAll(' ', '%')+'%';
        let pagina = request.query.pagina;
        if (pagina === undefined)
        {    pagina = 0;
        }
        const result = await pool.query('SELECT nome FROM funcionario WHERE nome ILIKE $1 OFFSET $2 LIMIT 5', [ nome , pagina*5 ]);
        response.status(200).json(result.rows);
    } catch (error) {
        console.log(error.stack);
        response.status(500).json(error.message);
    }
});

// Rota GET para buscar os dados completos de um funcionário específico através do seu código informado nos parâmetros da URL.
server.get('/funcionario/:codigo', async (request, response) => {
    try {
        console.log(request.params.codigo);
        
        const result = await pool.query('SELECT * FROM funcionario WHERE codigo = $1', [ request.params.codigo ]);
        if (result.rows.length == 0) {
            response.status(404).json();
            return;
        }
        response.status(200).json(result.rows[0]);
    } catch (error) {
        console.log(error.stack);
        response.status(500).json(error.message);
    }
});

// Rota PUT para atualizar os dados cadastrais (nome, salário e papel) de um funcionário específico, restrita ao papel 1.
server.put('/funcionario/:codigo', rolesMiddleware([ 1 ]), async (request, response) => {
    try {
        const result = await pool.query('UPDATE funcionario SET nome = $1, salario = $2, papel = $3 WHERE codigo = $4 RETURNING *', [ request.body.nome, request.body.salario, request.body.comissao, request.params.codigo ]);
        console.log(result.rows[0]);
        if (result.rows.length == 0) {
            response.status(404).json();
            return;
        }
        response.status(200).json(result.rows[0]);
    } catch (error) {
        console.log(error.stack);
        response.status(500).json(error.message);
    }
});

// Rota POST para cadastrar um novo funcionário com tratamento de normalização de nome para evitar duplicatas, restrita aos papéis 1 e 3.
server.post('/funcionario', rolesMiddleware([ 1, 3 ]), async (request, response) => {
    try {
        request.body.nome = request.body.nome.normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase().replace(/ +/g, ' ').trim();
        const result1 = await pool.query('SELECT * FROM funcionario WHERE nome = $1', [ request.body.nome ]);
        if (result1.rows.length != 0) {
            response.status(409).json();
            return;
        }
        const result2 = await pool.query('INSERT INTO funcionario (nome, salario, papel, senha) VALUES ($1, $2, $3, $4) RETURNING *', [ request.body.nome, request.body.salario, request.body.papel, bcrypt.hashSync(request.body.senha, 10) ]);
        console.log(result2.rows[0]);
        response.status(201).json(result2.rows[0]);
    } catch (error) {
        console.log(error.stack);
        response.status(500).json(error.message);
    }
});







// Rota GET para listar produtos com paginação e filtro opcional por características/descrição.
server.get('/produto', async (request, response) => {
    try {
        let caracteristicas = request.query.caracteristicas;
        if (caracteristicas === undefined)
        {    caracteristicas = '';
        }
        caracteristicas = '%'+caracteristicas.replaceAll(' ', '%')+'%';
        let pagina = request.query.pagina;
        if (pagina === undefined)
        {    pagina = 0;
        }
        const result = await pool.query('SELECT descricao, preco, quantidade FROM produto WHERE descricao ILIKE $1 OFFSET $2 LIMIT 5', [ caracteristicas, pagina*5 ]);
        response.status(200).json(result.rows);
    } catch (error) {
        console.log(error.stack);
        response.status(500).json(error.message);
    }
});

// Rota GET para buscar os detalhes de um produto específico com base no código fornecido nos parâmetros da URL.
server.get('/produto/:codigo', async (request, response) => {
    try {
        const result = await pool.query('SELECT descricao, preco, quantidade FROM produto WHERE codigo = $1', [ request.params.codigo ]);
        if (result.rows.length == 0) {
            response.status(404).json();
            return;
        }
        response.status(200).json(result.rows[0]);
    } catch (error) {
        console.log(error.stack);
        response.status(500).json(error.message);
    }
});

// Rota POST para cadastrar um novo produto com quantidade inicial zero e verificação de duplicidade de descrição, restrita ao papel 1.
server.post('/produto', rolesMiddleware([ 1 ]), async (request, response) => {
    try {
        request.body.descricao = request.body.descricao.normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase().replace(/ +/g, ' ').trim();
        const result1 = await pool.query('SELECT * FROM produto WHERE descricao = $1', [ request.body.descricao ]);
        if (result1.rows.length != 0) {
            response.status(409).json();
            return;
        }
        const result2 = await pool.query('INSERT INTO produto (descricao, preco, comissao, quantidade) VALUES ($1, $2, $3, 0) RETURNING *', [ request.body.descricao, request.body.preco, request.body.comissao ]);
        console.log(result2.rows[0]);
        response.status(201).json(result2.rows[0]);
    } catch (error) {
        console.log(error.stack);
        response.status(500).json(error.message);
    }
});

// Rota PUT para atualizar as informações (descrição, preço e comissão) de um produto existente, restrita ao papel 1.
server.put('/produto/:codigo', rolesMiddleware([ 1 ]), async (request, response) => {
    try {
        request.body.descricao = request.body.descricao.normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase().replace(/ +/g, ' ').trim();
        const result = await pool.query('UPDATE produto SET descricao = $1, preco = $2, comissao = $3 WHERE codigo = $4 RETURNING *', [ request.body.descricao, request.body.preco, request.body.comissao, request.params.codigo ]);
        console.log(result.rows[0]);
        if (result.rows.length == 0) {
            response.status(404).json();
            return;
        }
        response.status(200).json(result.rows[0]);
    } catch (error) {
        console.log(error.stack);
        response.status(500).json(error.message);
    }
});

// Rota PUT para registrar a entrada de estoque de um produto de forma transacional com bloqueio de linha (FOR UPDATE), restrita ao papel 1.
server.put('/produto/:codigo/entrada/:quantidade', rolesMiddleware([ 1 ]), async (request, response) => {
    let client;
    try {
        client = await pool.connect();
        await client.query('BEGIN');
        const result1 = await client.query('SELECT * FROM produto WHERE codigo = $1 FOR UPDATE', [ request.params.codigo ]);
        if (result1.rows.length == 0) {
            const error = new Error();
            error.status = 404;
            throw error;
        }
        const result2 = await client.query('UPDATE produto SET quantidade = quantidade + $1 WHERE codigo = $2 RETURNING *', [ request.params.quantidade, request.params.codigo ]);
        console.log(result2.rows[0]);
        await client.query('COMMIT');
        response.status(200).json(result2.rows[0]);
    } catch (error) {
        if (client) {
            await client.query('ROLLBACK');
        }
        console.log(error.stack);
        response.status(error.status || 500).json(error.message);
    } finally {
        if (client) {
            client.release();
        }
    }
});

// Rota PUT para registrar a saída de estoque de um produto com validação de saldo disponível de forma transacional.
server.put('/produto/:codigo/saida/:quantidade', async (request, response) => {
    let client;
    try {
        client = await pool.connect();
        await client.query('BEGIN');
        const result1 = await client.query('SELECT * FROM produto WHERE codigo = $1 FOR UPDATE', [ request.params.codigo ]);
        if (result1.rows.length == 0) {
            const error = new Error();
            error.status = 404;
            throw error;
        }
        if (result1.rows[0].quantidade < request.params.quantidade) {
            const error = new Error();
            error.status = 409;
            throw error;
        }
        const result2 = await client.query('UPDATE produto SET quantidade = quantidade - $1 WHERE codigo = $2 RETURNING *', [ request.params.quantidade, request.params.codigo ]);
        console.log(result2.rows[0]);
        await client.query('COMMIT');
        response.status(200).json(result2.rows[0]);
    } catch (error) {
        if (client) {
            await client.query('ROLLBACK');
        }
        console.log(error.stack);
        response.status(error.status || 500).json(error.message);
    } finally {
        if (client) {
            client.release();
        }
    }
});

// Rota GET para listar vendas com paginação e múltiplas combinações de filtros opcionais (data inicial, data final e vendedor), restrita ao papel 1.
server.get('/venda', rolesMiddleware([ 1 ]), async (request, response) => {
    try {
        let pagina = request.query.pagina;
        if (pagina === undefined)
        {    pagina = 0;
        }
        let result = null;
        if ((request.query.inicio === undefined) && (request.query.fim === undefined) && (request.query.vendedor === undefined))
        {    result = await pool.query('SELECT * FROM venda OFFSET $1 LIMIT 5', [ pagina*5 ]);
        }
        if ((request.query.inicio !== undefined) && (request.query.fim === undefined) && (request.query.vendedor === undefined))
        {    result = await pool.query('SELECT * FROM venda WHERE quando >= $1 OFFSET $2 LIMIT 5', [ request.query.inicio, pagina*5 ]);
        }
        if ((request.query.inicio === undefined) && (request.query.fim !== undefined) && (request.query.vendedor === undefined))
        {    result = await pool.query('SELECT * FROM venda WHERE quando <= $1 OFFSET $2 LIMIT 5', [ request.query.fim, pagina*5 ]);
        }
        if ((request.query.inicio !== undefined) && (request.query.fim !== undefined) && (request.query.vendedor === undefined))
        {    result = await pool.query('SELECT * FROM venda WHERE quando >= $1 AND quando <= $2 OFFSET $3 LIMIT 5', [ request.query.inicio, request.query.fim, pagina*5 ]);
        }
        if ((request.query.inicio === undefined) && (request.query.fim === undefined) && (request.query.vendedor !== undefined))
        {    result = await pool.query('SELECT * FROM venda WHERE vendedor = $1 OFFSET $2 LIMIT 5', [ request.query.vendedor, pagina*5 ]);
        }
        if ((request.query.inicio !== undefined) && (request.query.fim === undefined) && (request.query.vendedor !== undefined))
        {    result = await pool.query('SELECT * FROM venda WHERE quando >= $1 AND vendedor = $2 OFFSET $3 LIMIT 5', [ request.query.inicio, request.query.vendedor, pagina*5 ]);
        }
        if ((request.query.inicio === undefined) && (request.query.fim !== undefined) && (request.query.vendedor !== undefined))
        {    result = await pool.query('SELECT * FROM venda WHERE quando <= $1 AND vendedor = $2 OFFSET $3 LIMIT 5', [ request.query.fim, request.query.vendedor, pagina*5 ]);
        }
        if ((request.query.inicio !== undefined) && (request.query.fim !== undefined) && (request.query.vendedor !== undefined))
        {    result = await pool.query('SELECT * FROM venda WHERE quando >= $1 AND quando <= $2 AND vendedor = $3 OFFSET $4 LIMIT 5', [ request.query.inicio, request.query.fim, request.query.vendedor, pagina*5 ]);
        }
        response.status(200).json(result.rows);
    } catch (error) {
        console.log(error.stack);
        response.status(500).json(error.message);
    }
});

// Rota POST para registrar uma nova venda, consumindo a rota interna de saída de estoque via fetch e registrando o vendedor autenticado (JWT).
server.post('/venda', async (request, response) => {
    try {
        const fetch_response = await fetch(`http://localhost:8080/produto/${request.body.produto}/saida/${request.body.quantidade}/`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'Authorization': request.headers.authorization
            }
        });
        if (!fetch_response.ok) {
            response.status(fetch_response.status).json();
            return;
        }
        const result = await pool.query('INSERT INTO venda (vendedor, produto, quando, quantidade) VALUES ($1, $2, current_timestamp, $3) RETURNING *', [ request.jwtpayload.sub, request.body.produto, request.body.quantidade ]);
        console.log(result);
        response.status(201).json(result.rows[0]);
    } catch (error) {
        console.log(error.stack);
        response.status(500).json(error.message);
    }
});


// Rota GET para buscar os detalhes de uma venda específica pelo seu código, restrita ao papel 1.
server.get('/venda/:codigo', rolesMiddleware([ 1 ]), async (request, response) => {
    try {
        const result = await pool.query('SELECT * FROM venda WHERE codigo = $1', [ request.params.codigo ]);
        if (result.rows.length == 0) {
            response.status(404).json();
            return;
        }
        response.status(200).json(result.rows[0]);
    } catch (error) {
        console.log(error.stack);
        response.status(500).json(error.message);
    }
});

// Rota DELETE para remover uma venda diretamente pelo seu código, restrita ao papel 1.
server.delete('/venda/:codigo', rolesMiddleware([ 1 ]), async (request, response) => {
    try {
        const result = await pool.query('DELETE FROM venda WHERE codigo = $1 RETURNING *', [ request.params.codigo ]);
        console.log(result);
        if (result.rows.length == 0) {
            response.status(404).json();
            return;
        }
        response.status(204).json();
    } catch (error) {
        console.log(error.stack);
        response.status(500).json(error.message);
    }
});


// Rota PUT para realizar o estorno de uma venda (validando limite de dias úteis e devolvendo a quantidade ao estoque), restrita ao papel 1.
server.put('/venda/:codigo/extorno', rolesMiddleware([ 1 ]), async (request, response) => {
    try {
        const vendaResult = await pool.query('SELECT * FROM venda WHERE codigo = $1', [ request.params.codigo ]);
        if (vendaResult.rows.length == 0) {
            response.status(404).json();
            return;
        }
        
        const venda = vendaResult.rows[0];
        const dataVenda = new Date(venda.quando);
        const hoje = new Date();
        
        // Calcula a diferença em dias úteis (desconsiderando finais de semana)
        let diasUteis = 0;
        let atual = new Date(dataVenda);
        atual.setHours(0, 0, 0, 0);
        
        const limite = new Date(hoje);
        limite.setHours(0, 0, 0, 0);
        
        while (atual < limite) {
            atual.setDate(atual.getDate() + 1);
            const diaDaSemana = atual.getDay();
            if (diaDaSemana !== 0 && diaDaSemana !== 6) {
                diasUteis++;
            }
        }
        
        if (diasUteis > 7) {
            response.status(409).json("Prazo de estorno excedido (máximo de 7 dias úteis).");
            return;
        }

        const fetch_response = await fetch(`http://localhost:8080/produto/${venda.produto}/entrada/${venda.quantidade}/`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'Authorization': request.headers.authorization
            }
        });
        
        if (!fetch_response.ok) {
            response.status(fetch_response.status).json();
            return;
        }
        
        const deleteResult = await pool.query('DELETE FROM venda WHERE codigo = $1 RETURNING *', [ request.params.codigo ]);
        response.status(200).json(deleteResult.rows[0]);
    } catch (error) {
        console.log(error.stack);
        response.status(500).json(error.message);
    }
});


server.use((error, request, response, next) => {
    console.log(error.stack);
    response.status(error.status || 500).json(error.message);
});

server.listen(port, () => {
    console.log(`Server listening at http://localhost:${port}`);
});
