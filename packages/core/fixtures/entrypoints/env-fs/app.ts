import fs from 'fs'

const dbUrl = process.env.DATABASE_URL
const port = process.env.PORT
const secret = process.env.JWT_SECRET

// repeated access — should be deduplicated
const dbUrl2 = process.env.DATABASE_URL

const filename = getUserInput()
const content = fs.readFileSync(filename, 'utf8')
const stream = fs.createReadStream(filename)

// literal path — should NOT be detected
const config = fs.readFileSync('./config.json', 'utf8')

declare function getUserInput(): string
