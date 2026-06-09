import { copyFileSync, mkdirSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const repoRoot = join(root, '..')
const sourceDir = join(root, 'node_modules/@fontsource/plus-jakarta-sans/files')
const webTargetDir = join(root, 'public/fonts')
const pdfTargetDir = join(repoRoot, 'backend/Assets/Fonts')

const webFiles = [
  'plus-jakarta-sans-latin-700-normal.woff2',
  'plus-jakarta-sans-latin-800-normal.woff2',
]

const pdfFiles = [
  'plus-jakarta-sans-latin-800-normal.woff',
]

mkdirSync(webTargetDir, { recursive: true })
mkdirSync(pdfTargetDir, { recursive: true })

for (const file of webFiles) {
  copyFileSync(join(sourceDir, file), join(webTargetDir, file))
}

for (const file of pdfFiles) {
  copyFileSync(join(sourceDir, file), join(pdfTargetDir, file))
}

console.log(`Synced ${webFiles.length} web font files to public/fonts/`)
console.log(`Synced ${pdfFiles.length} PDF font file to backend/Assets/Fonts/`)
