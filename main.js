const path = require('path');
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const { body, validationResult } = require('express-validator');

const app = express();

app.use(bodyParser.json());
app.use(cookieParser());

const roles = {
  USER: 'user',
  ADMIN: 'admin',
  MODERATOR: 'moderator',
};

const applications = [];
const departments = ['HR', 'IT', 'Finance'];

const users = [];

app.get('/register', (req, res) => {
  const registrationPagePath = path.join(__dirname, 'views', 'registration.html');
  res.sendFile(registrationPagePath);
});

app.post('/register', [
  body('username').isString().notEmpty(),
  body('password').isString().notEmpty(),
  body('department').isIn(departments),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { username, password, department } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  if (users.some(user => user.username === username)) {
    return res.status(400).json({ error: 'Username already exists' });
  }

  users.push({ username, role: roles.USER, department, password: hashedPassword });

  // Возвращаем JSON с URL для редиректа
  res.json({ redirectUrl: '/success?reg=true' });
});

app.get('/success', (req, res) => {
  const regSuccess = req.query.reg === 'true';
  const successPagePath = path.join(__dirname, 'views', 'success.html');
  res.sendFile(successPagePath);
});

app.get('/login', (req, res) => {
  const loginPagePath = path.join(__dirname, 'views', 'login.html');
  res.sendFile(loginPagePath);
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = users.find(user => user.username === username);

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const token = jwt.sign({ username, role: user.role, department: user.department }, 'your-secret-key');

  res.cookie('token', token, { httpOnly: true });
  res.cookie('role', user.role, { httpOnly: false });

  res.json({ token });
});

app.post('/logout', (req, res) => {
  res.clearCookie('token');
  res.clearCookie('role');
  res.json({ success: true });
});

app.get('/', (req, res) => {
  const token = req.cookies.token;
  const role = req.cookies.role;

  if (token) {
    jwt.verify(token, 'your-secret-key', (err, user) => {
      if (!err) {
        res.send(`Welcome, ${user.username}! Role: ${role}, Department: ${user.department}`);
        return;
      }
    });
  }

  res.send('Welcome to the Role-based Application System');
});

function authenticateToken(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: 'Access denied' });

  jwt.verify(token, 'your-secret-key', (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
}

app.get('/protected', authenticateToken, (req, res) => {
  res.json({ message: 'This is a protected route', user: req.user });
});

app.post('/apply', authenticateToken, (req, res) => {
  const { username, role, department, description } = req.body;

  if (!departments.includes(department)) {
    return res.status(400).json({ error: 'Invalid department' });
  }

  applications.push({ username, role, department, description });
  res.json({ success: true });
});

app.post('/submit-application', authenticateToken, (req, res) => {
  const { title, text } = req.body;

  const token = req.cookies.token;
  jwt.verify(token, 'your-secret-key', (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }

    applications.push({ username: user.username, role: user.role, department: user.department, title, text });
    res.json({ success: true });
  });
});

app.get('/view-applications', authenticateToken, (req, res) => {
  const token = req.cookies.token;
  jwt.verify(token, 'your-secret-key', (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }

    if (user.role === roles.ADMIN || user.role === roles.MODERATOR) {
      res.json(applications);
    } else {
      res.status(403).json({ error: 'Access denied' });
    }
  });
});

app.delete('/delete-application/:id', authenticateToken, (req, res) => {
  const token = req.cookies.token;
  jwt.verify(token, 'your-secret-key', (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }

    const id = parseInt(req.params.id);

    if (user.role === roles.ADMIN || user.role === roles.MODERATOR) {
      const index = applications.findIndex(app => app.id === id);
      if (index !== -1) {
        applications.splice(index, 1);
        res.json({ success: true });
      } else {
        res.status(404).json({ error: 'Application not found' });
      }
    } else {
      res.status(403).json({ error: 'Access denied' });
    }
  });
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
