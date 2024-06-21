import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import User from '../models/User.js';

export const registerUser = async (req, res) => {
  const { name, email, password } = req.body;
  
  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: "Usuário já existe." });

    const hashedPassword = await bcrypt.hash(password, 12);
    
    const result = await User.create({ name, email, password: hashedPassword });
    
    res.status(201).json({ message: "Usuário registrado com sucesso!", result });
  } catch (error) {
    res.status(500).json({ message: "Algo deu errado." });
  }
};

export const loginUser = async (req, res) => {
  const { email, password } = req.body;

  try {
    const existingUser = await User.findOne({ email });
    if (!existingUser) return res.status(404).json({ message: "Usuário não encontrado." });

    const isPasswordCorrect = await bcrypt.compare(password, existingUser.password);
    if (!isPasswordCorrect) return res.status(400).json({ message: "Credenciais inválidas." });

    const token = jwt.sign({ email: existingUser.email, id: existingUser._id }, 'secret', { expiresIn: "1h" });

    res.status(200).json({ result: existingUser, token });
  } catch (error) {
    res.status(500).json({ message: "Algo deu errado." });
  }
};
