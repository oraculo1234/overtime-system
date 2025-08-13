import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
sqlite3.verbose();

export const db = await open({
  filename: './overtime.db',
  driver: sqlite3.Database
});
