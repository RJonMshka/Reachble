import Fastify from 'fastify'

const fastify = Fastify({ logger: true })

fastify.get('/health', handler)
fastify.post('/login', loginHandler)
fastify.route({ method: 'GET', url: '/items', handler: listItems })
fastify.addHook('preHandler', authenticate)

declare function handler(...args: unknown[]): void
declare function loginHandler(...args: unknown[]): void
declare function listItems(...args: unknown[]): void
declare function authenticate(...args: unknown[]): void
