import {build} from 'esbuild';
import {mkdir, copyFile, readFile, writeFile} from 'node:fs/promises';
await mkdir('web/dist', {recursive: true});
for (const entry of ['dashboard', 'audit-worker']) {
  await build({entryPoints: [`web/${entry}.js`], outfile: `web/dist/${entry}.js`,
    bundle: true, minify: true, format: 'iife', target: 'chrome120', legalComments: 'eof'});
}
await copyFile('web/index.html', 'web/dist/index.html');
await copyFile('web/style.css', 'web/dist/style.css');
await writeFile('web/dist/licenses.txt', 'hash-wasm 4.12.0\n\n' + await readFile('web/vendor/HASH-WASM-LICENSE', 'utf8') + '\nProject license\n\n' + await readFile('LICENSE','utf8'));
console.log('Offline dashboard and worker bundled');
