const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const db = require('./database');
const app = express();
const http = require('http').createServer(app);
const io = require('socket.io')(http);
const port = 3000;

app.set('io', io);
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));

app.use(session({
  secret: 'chave_secreta_segura',
  resave: false,
  saveUninitialized: false
}));

app.get('/', (req, res) => {
  res.redirect('/login');
});

// 🏠 Tela de cadastro
app.get('/register', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="pt-br">
    <head>
      <meta charset="UTF-8" />
      <title>Cadastro</title>
      <link href="https://fonts.googleapis.com/css2?family=Lexend&display=swap" rel="stylesheet">
      <link href="https://fonts.googleapis.com/css2?family=Lexend:wght@900&display=swap" rel="stylesheet">
      <link rel="stylesheet" href="/general.css" />
      <link rel="stylesheet" href="/register.css" />
    </head>
    <body>
      <div class="register-container">
        <h2>Cadastrar novo usuário</h2>
        <form action="/register" method="POST">
            
            <div class="nome-container">
              <label for="nome">Nome completo</label>
              <input type="text" name="nome" required/>
            </div>

            <div class="email-container">
              <label for="email">E-mail</label>
              <input type="email" name="email" required/>
            </div>

            <div class="senha-container">
              <label for="senha">Senha</label>
              <input type="password" name="senha" required/>
            </div>

            <div class="confirmar-senha-container">
              <label for="confirmar_senha">Confirmar senha</label>
              <input type="password" name="confirmar_senha" required/>
            </div>

            <button type="submit">Cadastrar</button>
        </form>
        <p>Já tem uma conta? <a href="/login">Fazer login</a></p>
      </div>
    </body>
    </html>
  `);
});

app.post('/register', (req, res) => {
  const { nome, email, senha, confirmar_senha } = req.body;

  if (senha !== confirmar_senha) {
  return res.send(`
    <!DOCTYPE html>
    <html lang="pt-br">
    <head>
      <meta charset="UTF-8" />
      <title>Erro no Cadastro</title>
      <style>
        body {
          background: rgba(0, 0, 0, 0.7);
          display: flex;
          align-items: center;
          justify-content: center;
          height: 100vh;
          margin: 0;
          font-family: Arial, sans-serif;
        }
        .modal {
          background: white;
          padding: 30px;
          border-radius: 10px;
          text-align: center;
          box-shadow: 0 0 10px rgba(0,0,0,0.5);
          position: relative;
        }
        .modal h2 {
          margin-top: 0;
          color: red;
        }
        .modal button {
          margin-top: 20px;
          padding: 8px 20px;
          background-color: red;
          color: white;
          border: none;
          border-radius: 5px;
          cursor: pointer;
        }
        .modal button:hover {
          background-color: darkred;
        }
      </style>
    </head>
    <body>
      <div class="modal">
        <h2>❌ Senhas não coincidem!</h2>
        <p>Por favor, verifique e tente novamente.</p>
        <button onclick="fecharModal()">OK</button>
      </div>

      <script>
        function fecharModal() {
          window.location.href = '/register';
        }
      </script>
    </body>
    </html>
  `);
}


  db.query('SELECT * FROM usuarios WHERE email = ?', [email], (err, results) => {
    if (err) throw err;

    if (results.length > 0) {
      return res.send(`
        <p>❌ Email já cadastrado.</p>
        <a href="/register">Voltar</a>
      `);
    }

    const hash = bcrypt.hashSync(senha, 8);

    db.query(
      'INSERT INTO usuarios (nome, email, senha) VALUES (?, ?, ?)',
      [nome, email, hash],
      (err) => {
        if (err) throw err;

        res.send(`
          <!DOCTYPE html>
          <html lang="pt-br">
          <head>
            <meta charset="UTF-8" />
            <title>Cadastro</title>
            <style>
              body {
                background: rgba(0, 0, 0, 0.7);
                display: flex;
                align-items: center;
                justify-content: center;
                height: 100vh;
                margin: 0;
                font-family: Arial, sans-serif;
              }
              .modal {
                background: white;
                padding: 30px;
                border-radius: 10px;
                text-align: center;
                box-shadow: 0 0 10px rgba(0,0,0,0.5);
              }
              .modal h2 {
                margin-top: 0;
              }
            </style>
          </head>
          <body>
            <div class="modal">
              <h2>✅ Usuário cadastrado com sucesso!</h2>
              <p>Redirecionando para o login...</p>
            </div>

            <script>
              setTimeout(() => {
                window.location.href = '/login';
              }, 1500);
            </script>
          </body>
          </html>
        `);
      }
    );
  });
});


app.post('/usuario/editar', async (req, res) => {
  if (!req.session.usuario) {
    return res.redirect('/login');
  }

  const userId = req.session.usuario.id;  // Assumindo que você guarda o ID do usuário na sessão
  const { nome, email, senha } = req.body;

  // Validações básicas
  if (!nome || !email) {
    return res.status(400).send('Nome e email são obrigatórios.');
  }

  try {
    let query = '';
    let params = [];

    if (senha && senha.trim() !== '') {
      // Se senha foi informada, gera hash e atualiza senha também
      const hash = await bcrypt.hash(senha, 10);
      query = 'UPDATE usuarios SET nome = ?, email = ?, senha = ? WHERE id = ?';
      params = [nome, email, hash, userId];
    } else {
      // Senha não informada, atualiza só nome e email
      query = 'UPDATE usuarios SET nome = ?, email = ? WHERE id = ?';
      params = [nome, email, userId];
    }

    db.query(query, params, (err, result) => {
      if (err) {
        console.error('Erro ao atualizar usuário:', err);
        return res.status(500).send('Erro ao atualizar usuário');
      }

      // Atualiza a sessão com os novos dados
      req.session.usuario.nome = nome;
      req.session.usuario.email = email;

      // Redireciona de volta para o dashboard ou mostra mensagem
      res.redirect('/dashboard');
    });
  } catch (error) {
    console.error('Erro na edição do usuário:', error);
    res.status(500).send('Erro interno');
  }
});


// 🔑 Tela de login
app.get('/login', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="pt-br">
    <head>
      <meta charset="UTF-8" />
      <title>Login</title>
      <link href="https://fonts.googleapis.com/css2?family=Lexend&display=swap" rel="stylesheet">
      <link href="https://fonts.googleapis.com/css2?family=Lexend:wght@900&display=swap" rel="stylesheet">
      <link rel="stylesheet" href="/general.css" />
      <link rel="stylesheet" href="/login.css" />
    </head>
    <body>
      <div class="login-container">
        <div class="logo-container">
          <img src="/logo2.png" alt="Logo" width="50px" />
          <h1>Organiza Ai</h1>
        </div>
        <form action="/login" method="POST">
            <label for="email">E-mail</label>
            <input id="email" type="email" name="email" required/>
            <label for="senha">Senha</label>
            <input id="senha" type="password" name="senha" required/>
            <button type="submit">Entrar</button>
        </form>
        <p>Não tem conta? <a href="/register">Cadastrar-se</a></p>
      </div>
    </body>
    </html>
    `);
});

app.post('/login', (req, res) => {
  const { email, senha } = req.body;

  db.query('SELECT * FROM usuarios WHERE email = ?', [email], (err, results) => {
    if (err) throw err;

    // Caso e-mail não encontrado
    if (results.length === 0) {
      return res.send(`
        <!DOCTYPE html>
        <html lang="pt-br">
        <head>
          <meta charset="UTF-8" />
          <title>Login</title>
          <style>
            body {
              background: rgba(0, 0, 0, 0.7);
              display: flex;
              align-items: center;
              justify-content: center;
              height: 100vh;
              margin: 0;
              font-family: Arial, sans-serif;
            }
            .modal {
              background: white;
              padding: 30px;
              border-radius: 10px;
              text-align: center;
              box-shadow: 0 0 10px rgba(0,0,0,0.5);
            }
            .modal h2 {
              margin-top: 0;
              color: red;
            }
          </style>
        </head>
        <body>
          <div class="modal">
            <h2>❌ Email não encontrado!</h2>
            <p>Redirecionando para login...</p>
          </div>

          <script>
            setTimeout(() => {
              window.location.href = '/login';
            }, 2000);
          </script>
        </body>
        </html>
      `);
    }

    const usuario = results[0];

    // Verificar senha incorreta
    if (!bcrypt.compareSync(senha, usuario.senha)) {
      return res.send(`
    <!DOCTYPE html>
    <html lang="pt-br">
    <head>
      <meta charset="UTF-8" />
      <title>Login</title>
      <style>
        body {
          background: rgba(0, 0, 0, 0.7);
          display: flex;
          align-items: center;
          justify-content: center;
          height: 100vh;
          margin: 0;
          font-family: Arial, sans-serif;
        }
        .modal {
          background: white;
          padding: 30px;
          border-radius: 10px;
          text-align: center;
          box-shadow: 0 0 10px rgba(0,0,0,0.5);
          position: relative;
        }
        .modal h2 {
          margin-top: 0;
          color: red;
        }
        .modal button {
          margin-top: 20px;
          padding: 8px 20px;
          background-color: red;
          color: white;
          border: none;
          border-radius: 5px;
          cursor: pointer;
        }
        .modal button:hover {
          background-color: darkred;
        }
      </style>
    </head>
    <body>
      <div class="modal">
        <h2>❌ Senha incorreta!</h2>
        <p>Por favor, tente novamente.</p>
        <button onclick="fecharModal()">OK</button>
      </div>

      <script>
        function fecharModal() {
          window.location.href = '/login';
        }
      </script>
    </body>
    </html>
  `);
    }


    // Login bem-sucedido
    req.session.usuario = {
      id: usuario.id,
      nome: usuario.nome,
      email: usuario.email
    };

    // Modal de sucesso
    res.send(`
      <!DOCTYPE html>
      <html lang="pt-br">
      <head>
        <meta charset="UTF-8" />
        <title>Login</title>
        <style>
          body {
            background: rgba(0, 0, 0, 0.7);
            display: flex;
            align-items: center;
            justify-content: center;
            height: 100vh;
            margin: 0;
            font-family: Arial, sans-serif;
          }
          .modal {
            background: white;
            padding: 30px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 0 10px rgba(0,0,0,0.5);
          }
          .modal h2 {
            margin-top: 0;
            color: green;
          }
        </style>
      </head>
      <body>
        <div class="modal">
          <h2>✅ Login realizado com sucesso!</h2>
        </div>

        <script>
          setTimeout(() => {
            window.location.href = '/dashboard';
          }, 1000);
        </script>
      </body>
      </html>
    `);
  });
});


app.get('/dashboard', (req, res) => {
  if (!req.session.usuario) {
    return res.redirect('/login');
  }

  const { nome } = req.session.usuario;

  res.send(`
        <head>
          <meta charset="UTF-8">
          <title>Dashboard</title>
          <link href="https://fonts.googleapis.com/css2?family=Lexend&display=swap" rel="stylesheet">
          <link href="https://fonts.googleapis.com/css2?family=Lexend:wght@900&display=swap" rel="stylesheet">
          <link rel="stylesheet" href="/general.css" />
          <link rel="stylesheet" href="/dashboard.css" />
        </head>
        <body>
          <div class="dashboard-container">

          <!------------------------------------------------------------------------------->
            <header class="header-container">
              <div class="header-content">
                
                <div class="logo-container">
                  <img src="/logo2.png" alt="Logo" width="35px" />
                  <p>Organiza Ai</p>
                </div>

                <div class="header-buttons">
                  <p>Usuário: ${nome}</p>
                  <button onclick="abrirModalEditarUsuario()">Perfil</button>
                  <a href="/logout">Sair</a>
                </div>
              
              </div>
              
              <div class="bar1"></div>
              <div class="bar2"></div>
            
            </header>
            <!--------------------------------------------------------------------------------->

            <!-- Modal Editar Usuário -->
            <div id="modalEditarUsuario" style="display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:#000000aa;align-items:center;justify-content:center;">
                <div style="background:#fff;padding:20px;min-width:300px;position:relative;">
                    <h3>Editar Perfil</h3>
                    <form id="formEditarUsuario" action="/usuario/editar" method="POST">
                        <label>Nome:</label><br/>
                        <input type="text" name="nome" id="editUserNome" value="${nome}" required /><br/><br/>

                        <label>E-mail:</label><br/>
                        <input type="email" name="email" id="editUserEmail" value="${req.session.usuario.email || ''}" required /><br/><br/>

                        <label>Senha (deixe em branco para não alterar):</label><br/>
                        <input type="password" name="senha" id="editUserSenha" placeholder="Nova senha" /><br/><br/>

                        <button type="submit">Salvar Alterações</button>
                        <button type="button" onclick="fecharModalEditarUsuario()">Cancelar</button>
                    </form>
                </div>
            </div>

            <main>
              <div class="main-content">
                
                <div class="main-content-left">
                  <h1>Gerenciar Tarefas</h1>
                </div>

                <div class="main-content-right">
                  <div class="criar-button">  
                    <button onclick="abrirModalCriar()">CRIAR</button>
                  </div>
                  <div class="filtro-container">
                    <nav>
                      <form id="formFiltros">
                        <div class="filtro-buttons">

                          <button type="submit">Filtrar</button>
                          <button type="button" onclick="limparFiltros()">Limpar Filtros</button>
                        </div>

                          <div class="tipos-filtro">
                            <label>Prioridade:
                              <select name="prioridade" id="filtroPrioridade">
                                <option>Todas</option>
                                <option>Baixo</option>
                                <option>Médio</option>
                                <option>Alto</option>
                              </select>
                            </label>
                            <label>Status:
                              <select name="status" id="filtroStatus">
                                <option>Todos</option>
                                <option>Pendente</option>
                                <option>Concluída</option>
                              </select>
                            </label>
                          </div>
                      </form>
                    </nav>
                  </div>
                </div>
              </div>

              <div id="tarefasContainer" style="margin-top:20px;">
                <p>Carregando tarefas...</p>
                <div class="loader"></div>
              </div>
            </main>

            <!-- Modal Criar -->
            <div id="modalCriar" style="display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:#000000aa;align-items:center;justify-content:center; z-index:1000;">
              <div style="background:#fff;padding:20px;min-width:300px;position:relative;">
                <h3>Criar Nova Tarefa</h3>
                <form id="formCriar" method="POST" action="/tarefa" onsubmit="return criarTarefa(event)">
                  <label>Título:</label><br/>
                  <input type="text" name="titulo" required/><br/><br/>

                  <label>Descrição:</label><br/>
                  <textarea name="descricao" required></textarea><br/><br/>

                  <label>Prioridade:</label><br/>
                  <select name="prioridade" required>
                    <option value="">Selecione</option>
                    <option value="Baixo">Baixo</option>
                    <option value="Médio">Médio</option>
                    <option value="Alto">Alto</option>
                  </select><br/><br/>

                  <button type="submit">Criar Tarefa</button>
                  <button type="button" onclick="fecharModalCriar()">Cancelar</button>
                </form>
              </div>
            </div>

            <!-- Modal Editar -->
            <div id="modal" style="display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:#000000aa;align-items:center;justify-content:center; z-index:1000;">
              <div style="background:#fff;padding:20px;min-width:300px;position:relative;">
                <h3>Tarefa</h3>
                <form id="formEditar" method="POST" onsubmit="return editarTarefa(event)">
                  <label>Título:</label><br/>
                  <input type="text" name="titulo" id="editTitulo" required/><br/><br/>

                  <label>Descrição:</label><br/>
                  <textarea name="descricao" id="editDescricao" required></textarea><br/><br/>

                  <label>Prioridade:</label><br/>
                  <select name="prioridade" id="editPrioridade" required>
                    <option value="Baixo">Baixo</option>
                    <option value="Médio">Médio</option>
                    <option value="Alto">Alto</option>
                  </select><br/><br/>

                  <label>Status:</label><br/>
                  <select name="status" id="editStatus" required>
                    <option value="Pendente">Pendente</option>
                    <option value="Concluída">Concluída</option>
                  </select><br/><br/>

                  <button type="submit">Salvar Alterações</button>
                  <button type="button" onclick="fecharModal()">Cancelar</button>
                </form>
              </div>
            </div>
      </div>
    </body>

    <script src="/socket.io/socket.io.js"></script>
    <script>
      const socket = io();

      socket.on('atualizarTarefas', () => {
        carregarTarefas();
      });

      async function carregarTarefas() {
        const prioridade = document.getElementById('filtroPrioridade').value;
        const status = document.getElementById('filtroStatus').value;

        const params = new URLSearchParams();
        if (prioridade !== 'Todas') params.append('prioridade', prioridade);
        if (status !== 'Todos') params.append('status', status);

        const container = document.getElementById('tarefasContainer');
        
        // Exibe loader enquanto carrega
        container.innerHTML = '<div class="loader"></div>';

        try {
            const res = await fetch('/api/tarefas?' + params.toString());
            
            if (!res.ok) throw new Error('Erro na requisição: ' + res.status);

            const tarefas = await res.json();

            // Limpa o container assim que chega a resposta
            container.innerHTML = '';

            if (tarefas.length === 0) {
                container.innerHTML = '<p>Nenhuma tarefa encontrada.</p>';
                return;
            }

            tarefas.forEach(tarefa => {
              const div = document.createElement('div');
              div.className = 'tarefa-item';

              // Adiciona classe baseada no status
              if (tarefa.status === 'Concluída') {
                  div.classList.add('status-concluida');
              } else if (tarefa.status === 'Pendente') {
                  div.classList.add('status-pendente');
              }

              div.innerHTML = \`
                  <div class="tarefa-info">
                      <strong>Por:</strong> \${tarefa.criador}<br/>
                      <strong>Título:</strong> \${tarefa.titulo}<br/>
                      <strong>Prioridade:</strong> \${tarefa.prioridade}<br/>
                      <strong>Status:</strong> <span class="status-text">\${tarefa.status}</span><br/>
                      <strong>Criado em:</strong> \${new Date(tarefa.data_criacao).toLocaleDateString()}<br/>
                  </div>
                  <div>
                      <button onclick="abrirModal(\${tarefa.id}, '\${tarefa.titulo.replace(/'/g, "\\\\'")}', '\${tarefa.descricao.replace(/'/g, "\\\\'")}', '\${tarefa.prioridade}', '\${tarefa.status}')">Ver</button>
                      <button onclick="alterarStatus(\${tarefa.id}, 'Concluída')">Concluída</button>
                      <button onclick="alterarStatus(\${tarefa.id}, 'Pendente')">Pendente</button>
                  </div>
              \`;

              container.appendChild(div);
          });


        } catch (err) {
            console.error('Erro ao carregar tarefas:', err);
            container.innerHTML = '<p style="color:red;">Erro ao carregar tarefas.</p>';
        }
    }


      function abrirModal(id, titulo, descricao, prioridade, status) {
        document.getElementById('editTitulo').value = titulo;
        document.getElementById('editDescricao').value = descricao;
        document.getElementById('editPrioridade').value = prioridade;
        document.getElementById('editStatus').value = status;

        document.getElementById('formEditar').dataset.id = id;
        document.getElementById('modal').style.display = 'flex';
      }

      function fecharModal() {
        document.getElementById('modal').style.display = 'none';
      }

      function abrirModalCriar() {
        document.getElementById('modalCriar').style.display = 'flex';
      }

      function fecharModalCriar() {
        document.getElementById('modalCriar').style.display = 'none';
      }

      function limparFiltros() {
        document.getElementById('filtroPrioridade').value = 'Todas';
        document.getElementById('filtroStatus').value = 'Todos';
        carregarTarefas();
      }

      document.getElementById('formFiltros').addEventListener('submit', e => {
        e.preventDefault();
        carregarTarefas();
      });

      async function alterarStatus(id, status) {
        try {
          await fetch('/tarefa/' + id + '/status', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({ status })
          });
          // Atualiza a lista após alteração
          carregarTarefas();
        } catch (err) {
          console.error('Erro ao alterar status:', err);
        }
      }

      async function criarTarefa(event) {
        event.preventDefault();
        const form = event.target;
        const formData = new URLSearchParams(new FormData(form));
        try {
          await fetch('/tarefa', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: formData
          });
          fecharModalCriar();
          carregarTarefas();
        } catch (err) {
          console.error('Erro ao criar tarefa:', err);
        }
        return false;
      }

      async function editarTarefa(event) {
        event.preventDefault();
        const form = event.target;
        const id = form.dataset.id;
        const formData = new URLSearchParams(new FormData(form));
        try {
          await fetch('/tarefa/' + id + '/editar', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: formData
          });
          fecharModal();
          carregarTarefas();
        } catch (err) {
          console.error('Erro ao editar tarefa:', err);
        }
        return false;
      }

      carregarTarefas();

      function abrirModalEditarUsuario() {
            document.getElementById('modalEditarUsuario').style.display = 'flex';
        }
        function fecharModalEditarUsuario() {
            document.getElementById('modalEditarUsuario').style.display = 'none';
        }
    </script>
  `);
});



// ➕ Criar tarefa
app.post('/tarefa', (req, res) => {
  if (!req.session.usuario) return res.redirect('/login');

  const { titulo, descricao, prioridade } = req.body;
  const usuarioId = req.session.usuario.id;

  const sql = 'INSERT INTO tarefas (titulo, descricao, prioridade, status, usuario_id, data_criacao) VALUES (?, ?, ?, "Pendente", ?, NOW())';

  db.query(sql, [titulo, descricao, prioridade, usuarioId], (err) => {
    if (err) throw err;

    // 🔥 Dispara atualização para todos os clientes
    const io = req.app.get('io');
    io.emit('atualizarTarefas');

    res.redirect('/dashboard');
  });
});


app.get('/api/tarefas', (req, res) => {
  if (!req.session.usuario) {
    return res.status(401).json({ error: 'Não autorizado' });
  }

  const { prioridade, status } = req.query;

  let sql = `
        SELECT tarefas.*, usuarios.nome AS criador 
        FROM tarefas 
        JOIN usuarios ON tarefas.usuario_id = usuarios.id
    `;
  const filtros = [];
  const params = [];

  if (prioridade && prioridade !== 'Todas') {
    filtros.push('tarefas.prioridade = ?');
    params.push(prioridade);
  }

  if (status && status !== 'Todos') {
    filtros.push('tarefas.status = ?');
    params.push(status);
  }

  if (filtros.length > 0) {
    sql += ' WHERE ' + filtros.join(' AND ');
  }

  sql += ' ORDER BY tarefas.data_criacao DESC';

  db.query(sql, params, (err, results) => {
    if (err) return res.status(500).json({ error: 'Erro no servidor' });

    res.json(results);
  });
});



// 🔄 Alterar status da tarefa
app.post('/tarefa/:id/status', (req, res) => {
  if (!req.session.usuario) return res.redirect('/login');

  const { id } = req.params;
  const { status } = req.body;

  const sql = 'UPDATE tarefas SET status = ? WHERE id = ?';

  db.query(sql, [status, id], (err) => {
    if (err) throw err;

    const io = req.app.get('io');
    io.emit('atualizarTarefas');

    res.redirect('/dashboard');
  });
});


app.post('/tarefa/:id/editar', (req, res) => {
  if (!req.session.usuario) return res.redirect('/login');

  const { id } = req.params;
  const { titulo, descricao, prioridade, status } = req.body;

  const sql = 'UPDATE tarefas SET titulo = ?, descricao = ?, prioridade = ?, status = ? WHERE id = ?';

  db.query(sql, [titulo, descricao, prioridade, status, id], (err) => {
    if (err) throw err;

    const io = req.app.get('io');
    io.emit('atualizarTarefas');

    res.redirect('/dashboard');
  });
});


// 🚪 Logout
app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login');
  });
});


// 🔥 Servidor rodando
http.listen(port, '0.0.0.0', () => {
  console.log(`Servidor rodando em http://localhost:${port}`);
});