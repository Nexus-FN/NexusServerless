import { Pool } from '@neondatabase/serverless';

const DATABASE_URL: string = 'postgres://Finninn:0cwyFrTxnY7K@ep-restless-night-902408.eu-central-1.aws.neon.tech/Nexus';

class db {

    getUserEmail = async (email: string) => {

        const pool = new Pool({ connectionString: DATABASE_URL });
        const client = await pool.connect();

        try {
            const res = await client.query('SELECT * FROM users WHERE email = $1', [email]);
            return res.rows[0];
        } finally {
            client.release();
        }

    };

    getUserAccountID = async (accountId: string) => {

        const pool = new Pool({ connectionString: DATABASE_URL });
        const client = await pool.connect();

        try {
            const res = await client.query('SELECT * FROM users WHERE accountid = $1', [accountId]);
            return res.rows[0];
        } finally {
            client.release();
        }

    };

    getUserUsername = async (username: string) => {

        const pool = new Pool({ connectionString: DATABASE_URL });
        const client = await pool.connect();

        try {
            const res = await client.query('SELECT * FROM users WHERE username = $1', [username]);
            return res.rows[0];
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

    getProfile = async (accountId: string) => {

        const pool = new Pool({ connectionString: DATABASE_URL });
        const client = await pool.connect();

        try {
            const res = await client.query('SELECT * FROM profiles WHERE accountid = $1', [accountId]);
            return res.rows[0];
        } finally {
            client.release();
        }

    };

    getFriends = async (accountId: string) => {

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