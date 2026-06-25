import fs from 'fs';
import path from 'path';

const fontPath = 'E:/DIMA/STUDY/4к2с/ВКР/OphthalmoGuide/frontend/public/fonts/plus-jakarta-sans-latin-800-normal.woff2';
const fontBuffer = fs.readFileSync(fontPath);
const base64Font = fontBuffer.toString('base64');

const cssSnippet = `@font-face {
  font-family: 'Plus Jakarta Sans';
  font-style: normal;
  font-weight: 800;
  font-display: swap;
  src: url('data:font/woff2;charset=utf-8;base64,${base64Font}') format('woff2');
  unicode-range: U+0000-00FF, U+0131, U+0152-0153, U+02BB-02BC, U+02C6, U+02DA, U+02DC, U+0304, U+0308, U+0329, U+2000-206F, U+20AC, U+2122, U+2191, U+2193, U+2212, U+2215, U+FEFF, U+FFFD;
}`;

fs.writeFileSync('E:/DIMA/STUDY/4к2с/ВКР/OphthalmoGuide/frontend/public/scratch_font_css.txt', cssSnippet);
console.log('Done!');

