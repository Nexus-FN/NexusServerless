import { Pool } from '@neondatabase/serverless';
import { Context } from 'hono';

const DATABASE_URL: string = c.env,DATBASE_URL;

class db {

    getUserEmail = async (email: string, c: any) => {

        const pool = new Pool({ connectionString: DATABASE_URL });
        const client = await pool.connect();

        try {

            let cachedUser = await c.env.USERCACHE.get(email);

            if (cachedUser) {
                console.log('Cache hit!');
                return JSON.parse(cachedUser);
            } else {
                console.log('Cache miss!');
                const res = await client.query('SELECT * FROM users WHERE email = $1', [email]);
                await c.env.USERCACHE.put(email, JSON.stringify(res.rows[0]), { expirationTtl: 600 });
                cachedUser = JSON.parse(await c.env.USERCACHE.get(email));
                return cachedUser;
            }
        } finally {
            client.release();
        }

    };

    getUserAccountID = async (accountId: string, c: any) => {

        const pool = new Pool({ connectionString: DATABASE_URL });
        const client = await pool.connect();

        try {

            let cachedUser = await c.env.USERCACHE.get(accountId);

            if (cachedUser) {
                console.log('Cache hit!');
                return JSON.parse(cachedUser);
            } else {
                console.log('Cache miss!');
                const res = await client.query('SELECT * FROM users WHERE accountid = $1', [accountId]);
                await c.env.USERCACHE.put(accountId, JSON.stringify(res.rows[0]), { expirationTtl: 600 });
                cachedUser = await JSON.parse(c.env.USERCACHE.get(accountId));
                return cachedUser;
            }
        } finally {
            client.release();
        }

    };

    getUserUsername = async (username: string, c: Context) => {

        const pool = new Pool({ connectionString: DATABASE_URL });
        const client = await pool.connect();

        try {

            let cachedUser = await c.env.USERCACHE.get(username);

            if (cachedUser) {
                console.log('Cache hit!');
                return JSON.parse(cachedUser);
            } else {
                console.log('Cache miss!');
                const res = await client.query('SELECT * FROM users WHERE username = $1', [username]);
                await c.env.USERCACHE.put(username, JSON.stringify(res.rows[0]), { expirationTtl: 600 });
                cachedUser = await JSON.parse(c.env.USERCACHE.get(username));
                return cachedUser;
            }
        } finally {
            client.release();
        }

    };

    updateUserEmail = async (email: string, key: string, value: string) => {

        const pool = new Pool({ connectionString: DATABASE_URL });
        const client = await pool.connect();

        try {
            const res = await client.query(`UPDATE users SET ${key} = $1 WHERE email = $2`, [value, email]);
            return res.rows[0];
        } finally {
            client.release();
        }

    };

    getProfile = async (accountId: string, c: any) => {

        let cachedProfile = await c.env.PROFILECACHE.get(accountId);

        const pool = new Pool({ connectionString: DATABASE_URL });
        const client = await pool.connect();

        if (cachedProfile) {
            console.log('Cache hit!');
            return JSON.parse(cachedProfile);
        } else {
            console.log('Cache miss!');
            const res = await client.query('SELECT * FROM profiles WHERE accountid = $1', [accountId]);
            return res.rows[0];
        }

    };

    getFriends = async (accountId: string, c: any) => {

        const pool = new Pool({ connectionString: DATABASE_URL });
        const client = await pool.connect();

        try {
            const res = await client.query('SELECT * FROM friends WHERE accountid = $1', [accountId]);
            return res.rows[0];
        } finally {
            client.release();
        }

    }

}

export default new db();
