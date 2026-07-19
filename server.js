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

server.get('/funcionario', rolesMiddleware([ 1, 3 ]), async (request, response) => {
	try {
	    let nome = request.query.nome;
		if (nome === undefined)
		{	nome = '';
		}
		nome = '%'+nome.replaceAll(' ', '%')+'%';
		let pagina = request.query.pagina;
		if (pagina === undefined)
		{	pagina = 0;
		}
		const result = await pool.query('SELECT nome FROM funcionario WHERE nome ILIKE $1 OFFSET $2 LIMIT 5', [ nome , pagina*5 ]);
		response.status(200).json(result.rows);
	} catch (error) {
		console.log(error.stack);
		response.status(500).json(error.message);
	}
});

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







server.get('/produto', async (request, response) => {
	try {
		let caracteristicas = request.query.caracteristicas;
		if (caracteristicas === undefined)
		{	caracteristicas = '';
		}
		caracteristicas = '%'+caracteristicas.replaceAll(' ', '%')+'%';
		let pagina = request.query.pagina;
		if (pagina === undefined)
		{	pagina = 0;
		}
		const result = await pool.query('SELECT descricao, preco, quantidade FROM produto WHERE descricao ILIKE $1 OFFSET $2 LIMIT 5', [ caracteristicas, pagina*5 ]);
		response.status(200).json(result.rows);
	} catch (error) {
		console.log(error.stack);
		response.status(500).json(error.message);
	}
});

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

server.get('/venda', rolesMiddleware([ 1 ]), async (request, response) => {
	try {
		let pagina = request.query.pagina;
		if (pagina === undefined)
		{	pagina = 0;
		}
		let result = null;
		if ((request.query.inicio === undefined) && (request.query.fim === undefined) && (request.query.vendedor === undefined))
		{	result = await pool.query('SELECT * FROM venda OFFSET $1 LIMIT 5', [ pagina*5 ]);
		}
		if ((request.query.inicio !== undefined) && (request.query.fim === undefined) && (request.query.vendedor === undefined))
		{	result = await pool.query('SELECT * FROM venda WHERE quando >= $1 OFFSET $2 LIMIT 5', [ request.query.inicio, pagina*5 ]);
		}
		if ((request.query.inicio === undefined) && (request.query.fim !== undefined) && (request.query.vendedor === undefined))
		{	result = await pool.query('SELECT * FROM venda WHERE quando <= $1 OFFSET $2 LIMIT 5', [ request.query.fim, pagina*5 ]);
		}
		if ((request.query.inicio !== undefined) && (request.query.fim !== undefined) && (request.query.vendedor === undefined))
		{	result = await pool.query('SELECT * FROM venda WHERE quando >= $1 AND quando <= $2 OFFSET $3 LIMIT 5', [ request.query.inicio, request.query.fim, pagina*5 ]);
		}
		if ((request.query.inicio === undefined) && (request.query.fim === undefined) && (request.query.vendedor !== undefined))
		{	result = await pool.query('SELECT * FROM venda WHERE vendedor = $1 OFFSET $2 LIMIT 5', [ request.query.vendedor, pagina*5 ]);
		}
		if ((request.query.inicio !== undefined) && (request.query.fim === undefined) && (request.query.vendedor !== undefined))
		{	result = await pool.query('SELECT * FROM venda WHERE quando >= $1 AND vendedor = $2 OFFSET $3 LIMIT 5', [ request.query.inicio, request.query.vendedor, pagina*5 ]);
		}
		if ((request.query.inicio === undefined) && (request.query.fim !== undefined) && (request.query.vendedor !== undefined))
		{	result = await pool.query('SELECT * FROM venda WHERE quando <= $1 AND vendedor = $2 OFFSET $3 LIMIT 5', [ request.query.fim, request.query.vendedor, pagina*5 ]);
		}
		if ((request.query.inicio !== undefined) && (request.query.fim !== undefined) && (request.query.vendedor !== undefined))
		{	result = await pool.query('SELECT * FROM venda WHERE quando >= $1 AND quando <= $2 AND vendedor = $3 OFFSET $4 LIMIT 5', [ request.query.inicio, request.query.fim, request.query.vendedor, pagina*5 ]);
		}
		response.status(200).json(result.rows);
	} catch (error) {
		console.log(error.stack);
		response.status(500).json(error.message);
	}
});

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


server.use((error, request, response, next) => {
	console.log(error.stack);
	response.status(error.status || 500).json(error.message);
});

server.listen(port, () => {
	console.log(`Server listening at http://localhost:${port}`);
});
