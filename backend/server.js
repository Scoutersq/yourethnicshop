/* global process */
import 'dotenv/config'
import bcrypt from 'bcryptjs'
import cors from 'cors'
import crypto from 'node:crypto'
import express from 'express'
import jwt from 'jsonwebtoken'
import mongoose from 'mongoose'
import nodemailer from 'nodemailer'

const app = express()
const port = Number(process.env.API_PORT || 8787)
const jwtSecret = process.env.JWT_SECRET || 'local-development-secret-change-me'
const mailer = process.env.SMTP_HOST ? nodemailer.createTransport({ host: process.env.SMTP_HOST, port: Number(process.env.SMTP_PORT || 587), secure: process.env.SMTP_SECURE === 'true', auth: { user: process.env.SMTP_USER, pass: (process.env.SMTP_PASSWORD || '').replace(/\s/g, '') } }) : null

app.use(cors({ origin: ['http://localhost:5173', 'http://127.0.0.1:5173'] }))
app.use(express.json({ limit: '1mb' }))

const productSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  category: { type: String, required: true, trim: true },
  price: { type: Number, required: true, min: 0 },
  oldPrice: { type: Number, required: true, min: 0 },
  tag: { type: String, default: '' },
  image: { type: String, required: true },
  color: { type: String, required: true },
}, { timestamps: true })

const orderSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  userEmail: { type: String, required: true },
  userName: { type: String, required: true },
  customer: {
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    phone: { type: String, required: true },
    address: { type: String, required: true },
    city: { type: String, required: true },
    pinCode: { type: String, required: true },
  },
  items: [{ productId: String, name: String, price: Number, quantity: Number }],
  total: { type: Number, required: true, min: 0 },
  paymentStatus: { type: String, default: 'pending' },
  orderStatus: { type: String, default: 'received' },
}, { timestamps: true })

const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  passwordHash: { type: String, required: true },
  phone: { type: String, default: '' },
  address: { type: String, default: '' },
  city: { type: String, default: '' },
  pinCode: { type: String, default: '' },
  otpHash: { type: String, default: null },
  otpExpiresAt: { type: Date, default: null },
  emailVerified: { type: Boolean, default: true },
}, { timestamps: true })

const Product = mongoose.model('Product', productSchema)
const Order = mongoose.model('Order', orderSchema)
const User = mongoose.model('User', userSchema)

const defaultProducts = [
  { name: 'Saffron Bloom Saree', category: 'Sarees', price: 4890, oldPrice: 6200, tag: 'Bestseller', image: 'https://images.unsplash.com/photo-1610030469983-98e550d6193c?auto=format&fit=crop&w=900&q=85', color: 'Marigold' },
  { name: 'The Gulabo Kurta Set', category: 'Kurta Sets', price: 3290, oldPrice: 4100, tag: 'New in', image: 'https://images.unsplash.com/photo-1583391733956-6c78276477e2?auto=format&fit=crop&w=900&q=85', color: 'Rose Pink' },
  { name: 'Moonlit Chanderi Anarkali', category: 'Dresses', price: 5490, oldPrice: 6800, tag: 'Limited', image: 'https://images.unsplash.com/photo-1594633312681-425c7b97ccd1?auto=format&fit=crop&w=900&q=85', color: 'Ivory' },
  { name: 'Aangan Cotton Co-ord', category: 'Co-ords', price: 2890, oldPrice: 3600, tag: '', image: 'https://images.unsplash.com/photo-1617627143750-d86bc21e42bb?auto=format&fit=crop&w=900&q=85', color: 'Indigo' },
  { name: 'Noor Handblock Kurta', category: 'Kurtas', price: 2190, oldPrice: 2750, tag: 'Everyday edit', image: 'https://images.unsplash.com/photo-1597983073493-88cd35cf93d0?auto=format&fit=crop&w=900&q=85', color: 'Terracotta' },
  { name: 'Champa Silk Blouse', category: 'Tops', price: 2490, oldPrice: 3100, tag: '', image: 'https://images.unsplash.com/photo-1564257577054-3e03c0c15b9f?auto=format&fit=crop&w=900&q=85', color: 'Almond' },
]

app.get('/api/health', (_request, response) => {
  response.json({ ok: true, database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected' })
})

app.get('/api/products', async (_request, response) => {
  try {
    response.json(await Product.find().sort({ createdAt: -1 }))
  } catch {
    response.status(500).json({ error: 'Unable to load products.' })
  }
})

app.post('/api/auth/signup', async (request, response) => {
  const signupEmail = String(request.body.email || '').trim().toLowerCase()
  try {
    const { name, password } = request.body
    if (!name || !signupEmail || !password || password.length < 6) return response.status(400).json({ error: 'Name, email, and a password of at least 6 characters are required.' })
    const passwordHash = await bcrypt.hash(password, 12)
    const otp = crypto.randomInt(100000, 1000000).toString()
    const user = await User.create({ name, email: signupEmail, passwordHash, emailVerified: false, otpHash: crypto.createHash('sha256').update(otp).digest('hex'), otpExpiresAt: new Date(Date.now() + 5 * 60 * 1000) })
    if (mailer) await mailer.sendMail({ from: process.env.SMTP_FROM || process.env.SMTP_USER, to: user.email, subject: 'Verify your yoursethnicshop account', text: `Your verification code is ${otp}. It expires in 5 minutes.` })
    else console.log(`Development signup OTP for ${user.email}: ${otp}`)
    response.status(201).json({ otpRequired: true, userId: user._id, email: user.email })
  } catch (error) {
    if (error.code === 11000) {
      const existing = await User.findOne({ email: signupEmail })
      if (existing && !existing.emailVerified) {
        const otp = crypto.randomInt(100000, 1000000).toString()
        existing.otpHash = crypto.createHash('sha256').update(otp).digest('hex')
        existing.otpExpiresAt = new Date(Date.now() + 5 * 60 * 1000)
        await existing.save()
        if (mailer) await mailer.sendMail({ from: process.env.SMTP_FROM || process.env.SMTP_USER, to: existing.email, subject: 'Verify your yoursethnicshop account', text: `Your verification code is ${otp}. It expires in 5 minutes.` })
        else console.log(`Development signup OTP for ${existing.email}: ${otp}`)
        return response.status(200).json({ otpRequired: true, userId: existing._id, email: existing.email })
      }
      return response.status(409).json({ error: 'This email is already registered. Please sign in instead.' })
    }
    response.status(400).json({ error: 'Account could not be created.' })
  }
})

app.post('/api/auth/login', async (request, response) => {
  const { email, password } = request.body
  const user = await User.findOne({ email: String(email || '').toLowerCase() })
  if (!user || !(await bcrypt.compare(password || '', user.passwordHash))) return response.status(401).json({ error: 'Email or password is incorrect.' })
  const otp = crypto.randomInt(100000, 1000000).toString()
  user.otpHash = crypto.createHash('sha256').update(otp).digest('hex')
  user.otpExpiresAt = new Date(Date.now() + 5 * 60 * 1000)
  await user.save()
  if (mailer) await mailer.sendMail({ from: process.env.SMTP_FROM || process.env.SMTP_USER, to: user.email, subject: 'Your yoursethnicshop verification code', text: `Your verification code is ${otp}. It expires in 5 minutes.` })
  else console.log(`Development OTP for ${user.email}: ${otp}`)
  response.json({ otpRequired: true, userId: user._id, email: user.email })
})

app.post('/api/auth/verify-otp', async (request, response) => {
  const { userId, otp } = request.body
  const user = await User.findById(userId)
  const hash = crypto.createHash('sha256').update(String(otp || '')).digest('hex')
  if (!user || !user.otpHash || user.otpExpiresAt < new Date() || user.otpHash !== hash) return response.status(401).json({ error: 'That OTP is invalid or expired.' })
  user.otpHash = null
  user.otpExpiresAt = null
  user.emailVerified = true
  await user.save()
  const token = jwt.sign({ sub: String(user._id), email: user.email }, jwtSecret, { expiresIn: '7d' })
  response.json({ token, id: user._id, name: user.name, email: user.email, phone: user.phone, address: user.address, city: user.city, pinCode: user.pinCode })
})

app.patch('/api/auth/:id/profile', async (request, response) => {
  try {
    const profile = (({ name, phone, address, city, pinCode }) => ({ name, phone, address, city, pinCode }))(request.body)
    const user = await User.findByIdAndUpdate(request.params.id, profile, { new: true, runValidators: true })
    if (!user) return response.status(404).json({ error: 'Account not found.' })
    response.json({ id: user._id, name: user.name, email: user.email, phone: user.phone, address: user.address, city: user.city, pinCode: user.pinCode })
  } catch (error) {
    response.status(400).json({ error: 'Profile could not be saved.', details: error.message })
  }
})

app.post('/api/products', async (request, response) => {
  try {
    const product = await Product.create(request.body)
    response.status(201).json(product)
  } catch (error) {
    response.status(400).json({ error: 'Product could not be created.', details: error.message })
  }
})

app.patch('/api/products/:id', async (request, response) => {
  try {
    const product = await Product.findByIdAndUpdate(request.params.id, request.body, { new: true, runValidators: true })
    if (!product) return response.status(404).json({ error: 'Product not found.' })
    response.json(product)
  } catch (error) {
    response.status(400).json({ error: 'Product could not be updated.', details: error.message })
  }
})

app.delete('/api/products/:id', async (request, response) => {
  try {
    const product = await Product.findByIdAndDelete(request.params.id)
    if (!product) return response.status(404).json({ error: 'Product not found.' })
    response.status(204).end()
  } catch (error) {
    response.status(400).json({ error: 'Product could not be removed.', details: error.message })
  }
})

app.post('/api/orders', async (request, response) => {
  try {
    const order = await Order.create(request.body)
    response.status(201).json({ orderId: order._id, status: order.orderStatus })
  } catch (error) {
    response.status(400).json({ error: 'Order could not be created.', details: error.message })
  }
})

app.get('/api/orders/user/:userId', async (request, response) => {
  try {
    const orders = await Order.find({ userId: request.params.userId }).sort({ createdAt: -1 })
    response.json(orders.map((order) => ({ orderId: order._id, items: order.items, total: order.total, paymentStatus: order.paymentStatus, orderStatus: order.orderStatus, createdAt: order.createdAt })))
  } catch {
    response.status(400).json({ error: 'Order history could not be loaded.' })
  }
})

async function start() {
  if (!process.env.MONGODB_URI) throw new Error('MONGODB_URI is missing from .env')
  await mongoose.connect(process.env.MONGODB_URI)
  if (await Product.countDocuments() === 0) await Product.insertMany(defaultProducts)
  if (mailer) await mailer.verify()
  app.listen(port, () => console.log(`yoursethnicshop API listening on http://localhost:${port}`))
}

start().catch((error) => {
  console.error('Unable to start MongoDB API:', error.message)
  process.exitCode = 1
})
