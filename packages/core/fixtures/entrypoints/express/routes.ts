import express from 'express'

const app = express()
const router = express.Router()

app.get('/users', getUsers)
app.post('/users', requireAuth, createUser)
app.delete('/users/:id', verifyAdmin, deleteUser)
app.use('/api', router)

router.get('/items', listItems)
router.put('/items/:id', checkPermission, updateItem)

declare function getUsers(...args: unknown[]): void
declare function requireAuth(...args: unknown[]): void
declare function createUser(...args: unknown[]): void
declare function verifyAdmin(...args: unknown[]): void
declare function deleteUser(...args: unknown[]): void
declare function listItems(...args: unknown[]): void
declare function checkPermission(...args: unknown[]): void
declare function updateItem(...args: unknown[]): void
