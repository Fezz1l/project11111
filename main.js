//main.js
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
  body('email').isEmail().notEmpty(),
  body('firstName').isString().notEmpty(),
  body('lastName').isString().notEmpty(),
  body('password').isString().notEmpty(),
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      console.error('Validation errors:', errors.array());
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, firstName, lastName, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    if (users.some(user => user.email === email)) {
      console.error('Email already exists');
      return res.status(400).json({ error: 'Email already exists' });
    }

    // Устанавливаем департамент по умолчанию в 'user'
    users.push({ email, firstName, lastName, role: roles.USER, department: 'user', password: hashedPassword });

    // Возвращаем JSON с URL для редиректа
    res.json({ redirectUrl: '/success?reg=true' });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
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
  const { email, password } = req.body;
  const user = users.find(user => user.email === email);

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const token = jwt.sign(
    {
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      role: user.role,
      department: user.department,
    },
    'your-secret-key'
  );

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

app.get('/post', (req, res) => {
  const postPagePath = path.join(__dirname, 'views', 'post.html');
  res.sendFile(postPagePath);
});

app.post('/post', (req, res) => {   
  const requestData = req.body;
  
  if (requestData && typeof requestData.inputString === 'string' && requestData.inputString.length === 1) {
    res.json({ success: true, message: 'Success', isValid: true });
  } else {
    res.json({ success: true, message: 'Success', isValid: false });
  }
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
