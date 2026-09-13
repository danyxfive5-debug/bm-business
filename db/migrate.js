import 'dotenv/config';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';

const { Pool } = pg;
if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL é obrigatória.');
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized:false } : false });
const dir = path.join(path.dirname(fileURLToPath(import.meta.url)), 'migrations');
const files = (await fs.readdir(dir)).filter(x=>x.endsWith('.sql')).sort();
for (const file of files) {
  console.log(`A aplicar ${file}...`);
  await pool.query(await fs.readFile(path.join(dir,file),'utf8'));
}
await pool.end();
console.log('Migrações concluídas.');
