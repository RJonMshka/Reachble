import express from 'express'
import { renderPage } from './routes/render.js'

const app = express()

app.use(express.json())

app.get('/render', renderPage)

app.listen(3000, () => {
  console.log('Demo server running on port 3000')
})
