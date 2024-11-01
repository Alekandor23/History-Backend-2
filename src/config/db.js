import pg from 'pg'

export const pool = new pg.Pool({
    user: 'historyhouse_user',
    host: 'dpg-cs2qhlo8fa8c73eguvm0-a.oregon-postgres.render.com',
    database: 'historyhouse',
    password: 'ckbyXt8RsNBWK9vztxOZvaq0ED1Z1cnl',
    port: 5432,
    ssl: {
      rejectUnauthorized: false
    }
})
  