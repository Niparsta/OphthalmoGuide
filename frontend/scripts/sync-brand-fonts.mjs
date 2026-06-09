import { copyFileSync, mkdirSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const sourceDir = join(root, 'node_modules/@fontsource/plus-jakarta-sans/files')
const webTargetDir = join(root, 'public/fonts')

const webFiles = [
  'plus-jakarta-sans-latin-700-normal.woff2',
  'plus-jakarta-sans-latin-800-normal.woff2',
]

mkdirSync(webTargetDir, { recursive: true })

for (const file of webFiles) {
  copyFileSync(join(sourceDir, file), join(webTargetDir, file))
}

console.log(`Synced ${webFiles.length} web font files to public/fonts/`)
