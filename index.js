import bcrypt from 'bcrypt';
import express from 'express';
import bodyParser from 'body-parser';
import jwt from 'jsonwebtoken';



const app = express();
app.use(bodyParser.json());

const JWT_SECRET = "myscretkey";

const users = []; // store users here

// SIGNUP
app.post('/signup', async (req, res) => {
  const { username, password } = req.body;

  // hash password
  const hashedPassword = await bcrypt.hash(password, 10);

  users.push({ username, password: hashedPassword });
  res.json({ message: "User registered successfully" });
});

// LOGIN
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  // find user
  const foundUser = users.find(u => u.username === username);
  if (!foundUser) return res.status(404).json({ message: "User not found" });

  // check password
  const isMatch = await bcrypt.compare(password, foundUser.password);

  if (isMatch) 
{
    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ message: "Login successful", token });
}
  else 
{
    res.status(401).json({ message: "Invalid credentials" });
}
});

app.get('/profile', (req, res) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(401).json({ message: "Token Missing" });

    const token = authHeader.split(' ')[1];

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: "UnAuthorized" });
        res.json({ message: `Welcome ${username}` });
    });
});


    
app.listen(3000, () => console.log('Server is running on port 3000'));
