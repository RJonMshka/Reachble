const { template, merge } = require('lodash')
const chalk = require('chalk')
const path = require('node:path')
const fs = require('fs')

const dynamicPkg = 'some-package'
const dyn = require(dynamicPkg)

module.exports = function example() {
  return template('hello') + merge({}) + chalk.red('x') + path.join('a') + fs.readFileSync('f') + dyn
}
