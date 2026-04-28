import { Command } from 'commander'

const program = new Command()

program
  .name('mytool')
  .description('a CLI tool')
  .argument('<input>', 'input file')
  .action((input: string) => {
    console.log(input)
  })

program.parse(process.argv)
