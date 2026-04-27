import { template, merge } from 'lodash'
import { red } from 'chalk'
import { join } from 'node:path'
import { readFileSync } from 'fs'
import type { Foo } from 'some-package'
import { bar as renamed } from '@scope/pkg'
import { baz } from '@scope/pkg/subpath'

export function example() {
  const t = template('hello <%= name %>')
  const m = merge({}, { a: 1 })
  console.log(red('error'), join('/'), readFileSync('file'), t, m)
  const _f: Foo = {} as Foo
  return renamed + baz
}
