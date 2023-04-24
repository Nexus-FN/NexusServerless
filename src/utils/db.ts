import { Pool } from "@neondatabase/serverless";
import { Context } from "hono";
class db {

    getUserEmail = async (email: string, c: any) => {
        try {

            let user;
            const pool = new Pool({ connectionString: c.env.DATABASE_URL });
            const { rows: [{ now }] } = await pool.query(`SELECT * FROM users WHERE email = "${email}"`);

            console.log(await rows[0]);

            //user = JSON.parse(await results[0]);
            return rows[0];
        } catch (err) {
            console.log(err);
        }
    };

    getUserAccountID = async (accountId: string, c: any) => {
        try {

            let user;


            const pool = new Pool({ connectionString: c.env.DATABASE_URL });
            const { rows: [{ now }] } = await pool.query(`SELECT * FROM users WHERE accountid = "${accountId}"`);


            console.log(await rows[0]);

            //user = JSON.parse(await results[0]);
            return results[0];
        } catch (err) {
            console.log(err);
        }
    };

    getUserUsername = async (username: string, c: Context) => {

        try {

            let user;


            const pool = new Pool({ connectionString: c.env.DATABASE_URL });
            const { rows: [{ now }] } = await pool.query(`SELECT * FROM users WHERE username = "${username}"`);


            console.log(await rows[0]);

            //user = JSON.parse(await results[0]);
            return rows[0];
        } catch (err) {
            console.log(err);
        }
    };

    updateUserEmail = async (email: string, key: string, value: string, c: any) => {

        try {

            let user;


          const pool = new Pool({ connectionString: c.env.DATABASE_URL });
          const { rows: [{ now }] } = await pool.query(`UPDATE users SET ${key} = $1 WHERE email = "${email}"`);


            console.log(await rows[0]);

            //user = JSON.parse(await results[0]);
            return rows[0];
        } catch (err) {
            console.log(err);
        }
    };

    getProfile = async (accountId: string, c: any) => {
        try {

            let user;

            const pool = new Pool({ connectionString: c.env.DATABASE_URL });
          const { rows: [{ now }] } = await pool.query(`SELECT * FROM profiles WHERE accountid = "${accountId}"`)

            console.log("Tried to get profile");

            //user = JSON.parse(await results[0]);
            return rows[0];
        } catch (err) {
            console.log(err);
        }
    };

    getFriends = async (accountId: string, c: any) => {
        try {

            let user;

            const pool = new Pool({ connectionString: c.env.DATABASE_URL });
            const { rows: [{ now }] } = await pool.query(`SELECT * FROM friends WHERE accountid = "${accountId}"`)


            console.log(await rows[0]);

            //user = JSON.parse(await results[0]);
            return rows[0];
        } catch (err) {
            console.log(err);
        }
    };
}

export default new db();
