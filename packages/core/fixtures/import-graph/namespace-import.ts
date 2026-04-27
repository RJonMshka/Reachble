import * as _ from 'lodash'
import * as path from 'node:path'

export function example() {
  return _.template('hello') + path.join('a', 'b')
}
