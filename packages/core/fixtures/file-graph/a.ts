import { template } from 'lodash'
import { helper } from './b'

export function render(tpl: string) {
  return template(helper(tpl))
}
