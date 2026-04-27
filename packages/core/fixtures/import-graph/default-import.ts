import lodash from 'lodash'
import chalk from 'chalk'

export function example() {
  return lodash.template('hello') + chalk.red('x')
}
