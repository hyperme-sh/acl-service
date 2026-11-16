// Inventory legal texts already shipped in the installed npm dependency tree.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
const root = process.argv[2];
const output = process.argv[3];
const rows = [];
function visit(dir) {
  for (const entry of fs.readdirSync(dir, {withFileTypes:true})) {
    if (!entry.isDirectory() || entry.isSymbolicLink()) continue;
    const current = path.join(dir,entry.name);
    const manifest = path.join(current,'package.json');
    if (fs.existsSync(manifest)) {
      const pkg = JSON.parse(fs.readFileSync(manifest));
      const texts = fs.readdirSync(current).filter(n => /^(licen[cs]e|notice|copying)([.-]|$)/i.test(n) && fs.statSync(path.join(current,n)).isFile());
      if (!texts.length) throw new Error(`Missing npm legal text: ${pkg.name}`);
      rows.push({name:pkg.name,version:pkg.version,license:pkg.license,
        texts:texts.map(n => ({path:path.relative(root,path.join(current,n)),sha256:crypto.createHash('sha256').update(fs.readFileSync(path.join(current,n))).digest('hex')}))});
      if (fs.existsSync(path.join(current,'node_modules'))) visit(path.join(current,'node_modules'));
    } else if (entry.name.startsWith('@')) visit(current);
  }
}
visit(root);
if (!rows.length) throw new Error('Empty npm legal inventory');
fs.writeFileSync(output,JSON.stringify(rows,null,2)+'\n');
console.log(`Indexed legal texts for ${rows.length} npm packages`);
