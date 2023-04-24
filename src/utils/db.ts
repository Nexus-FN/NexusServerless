import { Pool } from "@neondatabase/serverless";
import { Context } from "hono";

const DATABASE_URL: string =
    "postgres://Finninn:0cwyFrTxnY7K@ep-restless-night-902408.eu-central-1.aws.neon.tech/Nexus";

class db {

    getUserEmail = async (email: string, c: any) => {
        try {

            let user;

            let { results } = await c.env.DB.prepare(`
            SELECT * FROM users WHERE email = "${email}"
          `).all()


            console.log(await results[0]);

            //user = JSON.parse(await results[0]);
            return results[0];
        } catch (err) {
            console.log(err);
        }
    };

    getUserAccountID = async (accountId: string, c: any) => {
        try {

            let user;

            let { results } = await c.env.DB.prepare(`
            SELECT * FROM users WHERE accountid = "${accountId}"
          `).all()


            console.log(await results[0]);

            //user = JSON.parse(await results[0]);
            return results[0];
        } catch (err) {
            console.log(err);
        }
    };

    getUserUsername = async (username: string, c: Context) => {

        try {

            let user;

            let { results } = await c.env.DB.prepare(`
            SELECT * FROM users WHERE username = "${username}"
          `).all()


            console.log(await results[0]);

            //user = JSON.parse(await results[0]);
            return results[0];
        } catch (err) {
            console.log(err);
        }
    };

    updateUserEmail = async (email: string, key: string, value: string, c: any) => {

        try {

            let user;

            let { results } = await c.env.DB.prepare(`
            UPDATE users SET ${key} = $1 WHERE email = "${email}",
          `).all()


            console.log(await results[0]);

            //user = JSON.parse(await results[0]);
            return results[0];
        } catch (err) {
            console.log(err);
        }
    };

    getProfile = async (accountId: string, c: any) => {
        try {

            let user;

            let { results } = await c.env.DB.prepare(`
            SELECT * FROM profiles
          `).all()

            console.log("Tried to get profile");

            //user = JSON.parse(await results[0]);
            return results[0];
        } catch (err) {
            console.log(err);
        }
    };

    getFriends = async (accountId: string, c: any) => {
        try {

            let user;

            let { results } = await c.env.DB.prepare(`
            SELECT * FROM friends
          `).all()


            console.log(await results[0]);

            //user = JSON.parse(await results[0]);
            return results[0];
        } catch (err) {
            console.log(err);
        }
    };
}

export default new db();
