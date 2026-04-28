export async function GET(request: Request) {
  return Response.json({ items: [] })
}

export async function POST(request: Request) {
  const body = await request.json()
  return Response.json({ created: true, body })
}
