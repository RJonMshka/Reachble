import axios from 'axios'

export async function fetch(url: string) {
  return axios.get(url)
}
