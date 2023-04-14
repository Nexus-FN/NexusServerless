import { Context, Hono } from 'hono'

const app = new Hono()

//@ts-ignore
import { JSONRequest } from '@worker-tools/json-fetch';
import jwt from '@tsndr/cloudflare-worker-jwt';
import { cache } from 'hono/cache'
import { prettyJSON } from 'hono/pretty-json'
import db from './utils/db'
import functions from './utils/functions'
import { uuid } from '@cfworker/uuid';
import profileManager from './utils/profileManager';
import { resetContent } from '@worker-tools/shed';

const JWT_SECRET: string = 'nexus';
const ATLAS_KEY: string = 's0iJyjBYCH004YlzTvxvgtJEHeYtx5VucAZLUgJHUlSSVj4WZC8NsfsjhJAjXPo0'

const clientTokens: any[] = [];
const refreshTokens: any[] = [];
const accessTokens: any[] = [];

const Clients: any[] = [];

const exchangeTokens = [];

import { Pool } from '@neondatabase/serverless';
const DATABASE_URL: string = 'postgres://Finninn:0cwyFrTxnY7K@ep-restless-night-902408.eu-central-1.aws.neon.tech/Nexus';

//Functions

async function getContentPages(c: any) {
	const memory: any | undefined = functions.GetVersionInfo(c);

	console.log(`\x1b[31mGetting content pages\x1b[0m`)

	const contentpages = JSON.parse(await c.env.CACHE.get("contentpages"));

	let Language = "en";

	try {
		if (c.req.header("accept-language")) {
			if (c.req.header("accept-language").includes("-") && c.req.header("accept-language") != "es-419") {
				Language = c.req.header("accept-language").split("-")[0];
			} else {
				Language = c.req.header("accept-language");
			}
		}
	} catch { }

	const modes = ["saveTheWorldUnowned", "battleRoyale", "creative", "saveTheWorld"];
	const news = ["savetheworldnews", "battleroyalenews"];

	try {
		modes.forEach(mode => {
			contentpages.subgameselectdata[mode].message.title = contentpages.subgameselectdata[mode].message.title[Language]
			contentpages.subgameselectdata[mode].message.body = contentpages.subgameselectdata[mode].message.body[Language]
		})
	} catch (err) { }

	try {
		if (memory.build < 5.30) {
			news.forEach(mode => {
				contentpages[mode].news.messages[0].image = "https://cdn.discordapp.com/attachments/927739901540188200/930879507496308736/discord.png";
				contentpages[mode].news.messages[1].image = "https://cdn.discordapp.com/attachments/1078414275367927868/1079394302796509267/T-AthenaBackpack-573-TV-transformed.png";
			})
		}
	} catch (err) { }

	try {
		contentpages.dynamicbackgrounds.backgrounds.backgrounds[0].stage = `season${memory.season}`;
		contentpages.dynamicbackgrounds.backgrounds.backgrounds[1].stage = `season${memory.season}`;

		if (memory.season == 10) {
			contentpages.dynamicbackgrounds.backgrounds.backgrounds[0].stage = "seasonx";
			contentpages.dynamicbackgrounds.backgrounds.backgrounds[1].stage = "seasonx";
		}

		if (memory.build == 11.31 || memory.build == 11.40) {
			contentpages.dynamicbackgrounds.backgrounds.backgrounds[0].stage = "Winter19";
			contentpages.dynamicbackgrounds.backgrounds.backgrounds[1].stage = "Winter19";
		}

		if (memory.build == 19.01) {
			contentpages.dynamicbackgrounds.backgrounds.backgrounds[0].stage = "winter2021";
			contentpages.dynamicbackgrounds.backgrounds.backgrounds[0].backgroundimage = "https://cdn.discordapp.com/attachments/927739901540188200/930880158167085116/t-bp19-lobby-xmas-2048x1024-f85d2684b4af.png";
			contentpages.subgameinfo.battleroyale.image = "https://cdn.discordapp.com/attachments/927739901540188200/930880421514846268/19br-wf-subgame-select-512x1024-16d8bb0f218f.jpg";
			contentpages.specialoffervideo.bSpecialOfferEnabled = "true";
		}

		if (memory.season == 20) {
			if (memory.build == 20.40) {
				contentpages.dynamicbackgrounds.backgrounds.backgrounds[0].backgroundimage = "https://cdn2.unrealengine.com/t-bp20-40-armadillo-glowup-lobby-2048x2048-2048x2048-3b83b887cc7f.jpg"
			} else {
				contentpages.dynamicbackgrounds.backgrounds.backgrounds[0].backgroundimage = "https://cdn2.unrealengine.com/t-bp20-lobby-2048x1024-d89eb522746c.png";
			}
		}

		if (memory.season == 21) {
			contentpages.dynamicbackgrounds.backgrounds.backgrounds[0].backgroundimage = "https://cdn2.unrealengine.com/s21-lobby-background-2048x1024-2e7112b25dc3.jpg"
		}
	} catch (err) { }

	return contentpages;
}

function createAccess(user: any, clientId: string, grant_type: string, deviceId: string, expiresIn: any) {

	let accessToken = jwt.sign({
		"app": "fortnite",
		"sub": user.accountid,
		"dvid": deviceId,
		"mver": false,
		"clid": clientId,
		"dn": user.username,
		"am": grant_type,
		"p": btoa(uuid()),
		"iai": user.accountid,
		"sec": 1,
		"clsvc": "fortnite",
		"t": "s",
		"ic": true,
		"jti": MakeID().replace(/-/ig, ""),
		"creation_date": new Date(),
		"hours_expire": expiresIn
	}, JWT_SECRET);

	return accessToken;
}

function createRefresh(user: any, clientId: string, grant_type: string, deviceId: string, expiresIn: any) {
	let refreshToken = jwt.sign({
		"sub": user.accountId,
		"dvid": deviceId,
		"t": "r",
		"clid": clientId,
		"am": grant_type,
		"jti": MakeID().replace(/-/ig, ""),
		"creation_date": new Date(),
		"hours_expire": expiresIn
	}, JWT_SECRET);

	refreshTokens.push({ accountId: user.accountId, token: `eg1~${refreshToken}` });

	return refreshToken;
}

function MakeID() {
	return uuid();
}

function createError(errorCode: string, errorMessage: string, messageVars: string[], numericErrorCode: number, error: any) {
	return {
		errorCode: errorCode,
		errorMessage: errorMessage,
		messageVars: messageVars,
		numericErrorCode: numericErrorCode,
		originatingService: "any",
		intent: "prod",
		error_description: errorMessage,
		error: error
	};
}

function createClient(clientId: string | undefined, grant_type: string, ip: string, expiresIn: any) {
	let clientToken = JSON.stringify(jwt.sign({
		"p": btoa(uuid.toString()),
		"clsvc": "fortnite",
		"t": "s",
		"mver": false,
		"clid": clientId,
		"ic": true,
		"am": grant_type,
		"jti": MakeID().replace(/-/ig, ""),
		"creation_date": new Date(),
		"hours_expire": expiresIn
	}, JWT_SECRET));

	clientTokens.push({ ip: ip, token: `eg1~${clientToken}` });

	return clientToken;
}

//Routes
app.use('*', async (c, next) => {
	console.log(`[${c.req.method}] ${c.req.url}`)
	await next()
})

app.use('*', prettyJSON())

app.get(
	'*',
	cache({
		cacheName: 'nexus',
		cacheControl: 'max-age=3600',
	})
)

app.onError((err, c) => {
	console.log(`\x1b[31m${err}\x1b[0m`)
	return c.text('An error has occured, Please contact @Zetax#7637 on Discord', 500)
})

app.notFound((c) => {
	return c.text('This Nexus route could not be found', 404)
})

app.get('/health', (c) => {
	return c.json({
		status: 'ok',
	})
})

app.get('/create/:user/:pass', async (c) => {

	const pool = new Pool({ connectionString: DATABASE_URL });
	const client = await pool.connect();

	const user = c.req.param('user');
	const pass = c.req.param('pass');

	const genUUID:any = uuid();

	const userResult = await client.query(`
      INSERT INTO users (created, discordId, accountId, username, username_lower, email, password)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING id, created, discordId, accountId, username, username_lower, email, reports, donator, affiliate, stats
    `, [new Date(), "327892412544581633", genUUID, 'Zetax', 'zetax', 'hazy-flower-03@icloud.com', pass]);

	const userId = userResult.rows[0].id;

	const profileResult = await client.query(`
      INSERT INTO profiles (created, accountId, profiles)
      VALUES ($1, $2, $3)
      RETURNING *
    `, [new Date(), genUUID, { }]);

	const profileId = profileResult.rows[0].id;

	const friendsResult = await client.query(`
      INSERT INTO friends (created, accountId, list)
      VALUES ($1, $2, $3)
      RETURNING *
    `, [new Date(), genUUID, { accepted: [], incoming: [], outgoing: [], blocked: [] }]);

	const friendsId = friendsResult.rows[0].id;

	return c.json({
		status: 'ok',
		userId: userId,
		profileId: profileId,
		friendsId: friendsId,
	})

});

app.get('/getuser/:accountId', async (c) => {

	const accountId:any = c.req.param('accountId');

	const user:any = await db.getUserAccountID(accountId);

	console.log(user.banned)

	return c.json({
		user: user,
	})

});

app.get('/vaultmp', async (c) => {

	//@ts-expect-error
	const shouldWork: boolean = c.env.TOKENS.get('shouldWork');
	if (shouldWork) {
		return c.json({
			status: 'ok',
		})
	} else {
		return c.json({
			status: 'error',
		})
	}

});

app.get('/getuser/:user', async (c) => {

	const user = c.req.param('user');

	//@ts-ignore
	const cachedUser = await c.env.TOKENS.get(user);
	if (cachedUser) {
		console.log('Found user in cache')
		const parsedUser = JSON.parse(cachedUser);
		return c.json({
			user: parsedUser,
		})
	} else {


		const response: any = await fetch(new JSONRequest('https://data.mongodb-api.com/app/data-tsmsh/endpoint/data/beta/action/findOne', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'apiKey': ATLAS_KEY
			},
			body: {
				"dataSource": "Nexus",
				"database": "Serverless",
				"collection": "users",
				"filter": {
					"username": user
				}
			}
		})).then(res => res.json());

		//@ts-ignore
		await c.env.TOKENS.put(user, JSON.stringify(response.document));
		console.log('User not found in cache, caching user')
		return c.json({
			user: response.document,
		})
	}

});

let error: { errorCode: string; errorMessage: string; messageVars: string[]; numericErrorCode: number; originatingService: string; intent: string; error_description: string; error: any; };

//Auth

app.post('/account/api/oauth/token', async (c) => {

	let clientId: any;

	const body: any = await c.req.parseBody();
	console.log("oauth: " + body.grant_type);
	console.log(body)


	const authorization = c.req.headers.get('authorization')

	if (authorization != null) {
		clientId = functions.DecodeBase64(authorization.split(" ")[1]).split(":");

		clientId = clientId[0];

		console.log("clientId: " + clientId);

	} else {
		error = createError(
			"errors.com.epicgames.common.oauth.invalid_client",
			"It appears that your Authorization header may be invalid or not present, please verify that you are sending the correct headers.",
			[], 1011, "invalid_client")
		console.log("oauth createerror authorization header invalid");
		return c.json(error, 400);
	}

	let clientip: string = c.req.header('CF-Connecting-IP') || 'noip';

	let requser: any;

	switch (body.grant_type as string) {

		case 'client_credentials':

			console.log("oauth: client_credentials");

			let clientToken = clientTokens.findIndex(i => i.ip == clientip);

			if (clientToken != -1) clientTokens.splice(clientToken, 1);

			const token = createClient(clientId, body.grant_type, clientip, 4);

			//@ts-ignore
			c.env.TOKENS.put(clientip, token)

			console.log("token: " + token);

			c.res.headers.set('Content-Type', 'application/json');

			let resBody = JSON.stringify({
				//@ts-ignore
				"access_token": `eg1~${token}`,
				"expires_in": 14400,
				"expires_at": "2021-05-01T20:00:00.000Z",
				"token_type": "bearer",
				"client_id": clientId,
				"internal_client": true,
				"client_service": "fortnite",
			});

			return c.json(resBody, 200, { 'Content-Type': 'application/json' });

			break;

		case 'password':

			console.log("oauth: password");

			if (!body.username || !body.password) {
				error = createError(
					"errors.com.epicgames.common.oauth.invalid_request",
					"Username/password is required.",
					[], 1013, "invalid_request")
				console.log("oauth createerror username/password is required: " + body.username + " " + body.password);
				return c.json(error, 400);
			}

			const { username: email, password: password } = body;

			const dbuser = await db.getUserEmail(email);

			requser = dbuser;

			error = createError(
				"errors.com.epicgames.account.invalid_account_credentials",
				"Your e-mail and/or password are incorrect. Please check them and try again.",
				[], 18031, "invalid_grant"
			);

			console.log("oauth: email: " + email);
			console.log("oauth: password: " + password);

			const msgUint8 = new TextEncoder().encode(password) // encode as (utf-8) Uint8Array
			const hashBuffer = await crypto.subtle.digest('MD5', msgUint8) // hash the message
			const hashArray = Array.from(new Uint8Array(hashBuffer)) // convert buffer to byte array
			const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('') // convert bytes to hex string

			if (dbuser.password !== hashHex) {
				console.log("oauth: error created: email or password incorrect. Hash is: " + hashHex);
				return c.json(error, 400);
			}

			console.log("oauth: email and password correct");

			break;

		case 'refresh_token':

			console.log("oauth: refresh_token");

			if (!body.refresh_token) {
				error = createError(
					"errors.com.epicgames.common.oauth.invalid_request",
					"Refresh token is required.",
					[], 1013, "invalid_request")
				console.log("oauth createerror refresh token is required");
				return c.json(error, 400);
			}

			const refresh_token = body.refresh_token;
			let refreshToken = refreshTokens.findIndex(i => i.token == refresh_token);
			let object = refreshTokens[refreshToken];

			try {

				console.log("oauth: refresh token step");

				jwt.verify(refresh_token.replace('eg1~', ''), JWT_SECRET);

				if (refreshToken == -1) {
					error = createError(
						"errors.com.epicgames.common.oauth.invalid_request",
						"Refresh token is invalid.",
						[], 1013, "invalid_request")
					console.log("oauth: refresh token invalid");
					return c.json(error, 400);
				}

			} catch {

				if (refreshToken != -1) refreshTokens.splice(refreshToken, 1);

				error = createError(
					"errors.com.epicgames.account.auth_token.invalid_refresh_token",
					`Sorry the refresh token '${refresh_token}' is invalid`,
					[refresh_token], 18036, "invalid_grant")
				console.log("oauth: refresh token invalid");
				return c.json(error, 400);

			}
			
			requser = await db.getUserAccountID(object.accountId)
			console.log("oauth: get user account id step for refresh token = " + requser);

			break;

		default:
			error = createError(
				"errors.com.epicgames.common.oauth.unsupported_grant_type",
				`Unsupported grant type: ${body.grant_type}`,
				[], 1016, "unsupported_grant_type")
			console.log("oauth: unsupported grant type");
			return c.json(error, 400);
	}

	if (await requser.banned == false) {
		console.log("oauth: account banned step + " + requser.banned);
		error = createError(
			"errors.com.epicgames.account.account_not_active",
			"Sorry, your account is inactive and may not login.",
			[], -1, undefined)
		console.log("oauth: account not active");
		return c.json(error, 400);
	}

	let accessIndex = accessTokens.findIndex(i => i.accountId == requser.accountId);
	if (accessIndex != -1) accessTokens.splice(accessIndex, 1);

	let refreshIndex = refreshTokens.findIndex(i => i.accountId == requser.accountId);
	if (refreshIndex != -1) refreshTokens.splice(refreshIndex, 1);

	const deviceId: string = uuid().replace(/-/g, "");

	const accessToken: any = await createAccess(requser, clientId, body.grant_type, deviceId, 8);

	const refreshToken: any = await createRefresh(requser, clientId, body.grant_type, deviceId, 8);

	//FIXME token.split is not a function

	console.log("Access token is " + await accessToken);

	const decodedAccess = jwt.decode(accessToken);
	const decodedRefresh = jwt.decode(refreshToken);

	let returnBody = {
		"access_token": `eg1~${accessToken}`,
		"expires_in": 14400,
		"expires_at": "2029-10-01T20:00:00.000Z",
		"token_type": "bearer",
		"refresh_token": `eg1~${refreshToken}`,
		"refresh_expires": 43200,
		"refresh_expires_at": "2029-10-01T20:00:00.000Z",
		"account_id": requser.accountid,
		"client_id": clientId,
		"internal_client": true,
		"client_service": "fortnite",
		"displayName": requser.username,
		"app": "fortnite",
		"in_app_id": requser.accountid,
		"device_id": deviceId
	}

	console.log(returnBody)

	console.log("oauth: return body created");

	return c.json(returnBody, 200);

});

app.get("/account/api/oauth/verify", async (c) => {

	const authorization: any = c.req.header("authorization");
	const body: any = await c.req.parseBody();

	if (authorization != undefined) {

		let token = authorization.replace("bearer ", "");
		const decodedToken: any = jwt.decode(token.replace("eg1~", ""));

		c.json({
			token: token,
			session_id: decodedToken.jti,
			token_type: "bearer",
			client_id: decodedToken.clid,
			internal_client: true,
			client_service: "fortnite",
			account_id: body.user.accountId,
			expires_in: new Date().getTime() + 14400,
			expires_at: new Date().toISOString(),
			auth_method: decodedToken.am,
			display_name: body.user.username,
			app: "fortnite",
			in_app_id: body.user.accountId,
			device_id: decodedToken.dvid
		});
	}
});


app.get('/account/api/oauth/exchange', async (c) => {

	return c.json({ "error": "This endpoint is deprecated, please use the discord bot to generate an exchange code." }, 400);

});

app.delete('/account/api/oauth/sessions/kill', async (c) => {

	return c.json(204);

});

app.get('/test/test', async (c) => {

	return c.json(204);

});

app.delete('/account/api/oauth/sessions/kill/:token', async (c) => {

	return c.json({});

});

//Cloud storage

app.get('/fortnite/api/cloudstorage/system', async (c) => {

	const CloudFiles: Array<Object> = [];

	try {

		return c.json([{ "uniqueFilename": "DefaultEngine.ini", "filename": "DefaultEngine.ini", "hash": "aff024fe4ab0fece4091de044c58c9ae4233383a", "hash256": "50e721e49c013f00c62cf59f2163542a9d8df02464efeb615d31051b0fddc326", "length": 942, "contentType": "application/octet-stream", "uploaded": "2023-04-13T13:00:35.726Z", "storageType": "S3", "storageIds": {}, "doNotCache": true }, { "uniqueFilename": "DefaultGame.ini", "filename": "DefaultGame.ini", "hash": "aff024fe4ab0fece4091de044c58c9ae4233383a", "hash256": "50e721e49c013f00c62cf59f2163542a9d8df02464efeb615d31051b0fddc326", "length": 11276, "contentType": "application/octet-stream", "uploaded": "2023-04-13T13:00:35.726Z", "storageType": "S3", "storageIds": {}, "doNotCache": true }, { "uniqueFilename": "DefaultInput.ini", "filename": "DefaultInput.ini", "hash": "aff024fe4ab0fece4091de044c58c9ae4233383a", "hash256": "50e721e49c013f00c62cf59f2163542a9d8df02464efeb615d31051b0fddc326", "length": 67, "contentType": "application/octet-stream", "uploaded": "2023-04-13T13:00:35.726Z", "storageType": "S3", "storageIds": {}, "doNotCache": true }, { "uniqueFilename": "DefaultRuntimeOptions.ini", "filename": "DefaultRuntimeOptions.ini", "hash": "aff024fe4ab0fece4091de044c58c9ae4233383a", "hash256": "50e721e49c013f00c62cf59f2163542a9d8df02464efeb615d31051b0fddc326", "length": 1135, "contentType": "application/octet-stream", "uploaded": "2023-04-13T13:00:35.727Z", "storageType": "S3", "storageIds": {}, "doNotCache": true }])

	} catch {

	}

	return c.json(CloudFiles, 200);

});

app.get('/fortnite/api/cloudstorage/system/:file', async (c) => {

	const fileName: string = c.req.param("file");

	let kv: any;


	if (c.env != null) {
		kv = c.env.CACHE;
	}

	switch (fileName) {

		case "DefaultEngine.ini":
			const DefaultEngine = await kv.get("DefaultEngine.ini")
			c.res.headers.set("Content-Type", "application/octet-stream");
			return c.text(DefaultEngine, 200);
			break;
		case "DefaultGame.ini":
			const DefaultGame = await kv.get("DefaultGame.ini")
			c.res.headers.set("Content-Type", "application/octet-stream");
			return c.text(DefaultGame, 200);
			break;
		case "DefaultInput.ini":
			const DefaultInput = await kv.get("DefaultInput.ini")
			c.res.headers.set("Content-Type", "application/octet-stream");
			return c.text(DefaultInput, 200);
			break;
		case "DefaultRuntimeOptions.ini":
			const DefaultRuntimeOptions = await kv.get("DefaultRuntimeOptions.ini")
			c.res.headers.set("Content-Type", "application/octet-stream");
			return c.text(DefaultRuntimeOptions, 200);
			break;

	}

});

app.get("/fortnite/api/cloudstorage/user/:accountId", async (c) => {
	c.res.headers.set("Content-Type", "application/octet-stream");
	return c.text("[]");
});

app.get("/fortnite/api/cloudstorage/user/*/:file", async (c) => {
	c.res.headers.set("Content-Type", "application/octet-stream");
	return c.text("[]");
});

app.put("/fortnite/api/cloudstorage/user/*/:file", async (c) => {

	c.res.headers.set("Content-Type", "application/octet-stream");
	return c.text("[]");

});


//TODO Contentpages

app.get('/content/api/pages/*', async (c) => {

	const contentpages = await getContentPages(c);

	return c.json(contentpages);

});

//TODO Friends

app.delete("/friends/api/v1/:accountId/friends/NexusBot", async (c) => {
	c.json({ "errorCode": "errors.com.epicgames.Nexus.common.forbidden", "errorMessage": "You cannot remove the bot", "messageVars": [], "numericErrorCode": 14004, "originatingService": "party", "intent": "prod" }, 403)
})

app.post("/friends/api/v1/:accountId/friends/NexusBot", async (c) => {
	c.json(204)
})

app.get("/friends/api/v1/*/settings", async (c) => {
	return c.json({});
});

app.get("/friends/api/v1/*/blocklist", async (c) => {
	return c.json([{}]);
});

app.get("/friends/api/public/list/fortnite/*/recentPlayers", async (c) => {
	return c.json([{}]);
});
app.get("/friends/api/public/friends/:accountId", async (c) => {
	let response: Array<Object> = [];

	console.log("friends: get friends for " + c.req.param("accountId") + "");

	const friends = await db.getFriends(c.req.param("accountId"));

	friends.list.accepted.forEach((acceptedFriend: { accountId: any; created: any; }) => {
		response.push({
			"accountId": acceptedFriend?.accountId || c.req.param("accountId"),
			"status": "ACCEPTED",
			"direction": "OUTBOUND",
			"created": acceptedFriend?.created || new Date(),
			"favorite": false
		})
	})

	friends.list.incoming.forEach((incomingFriend: { accountId: any; created: any; }) => {
		response.push({
			"accountId": incomingFriend?.accountId || c.req.param("accountId"),
			"status": "PENDING",
			"direction": "INBOUND",
			"created": incomingFriend?.created || new Date(),
			"favorite": false
		})
	})

	friends.list.outgoing.forEach((outgoingFriend: { accountId: any; created: any; }) => {
		response.push({
			"accountId": outgoingFriend.accountId || c.req.param("accountId"),
			"status": "PENDING",
			"direction": "OUTBOUND",
			"created": outgoingFriend?.created || new Date(),
			"favorite": false
		});
	});

	return c.json(response);
});


//TODO Lightswitch

app.get('/lightswitch/api/service/Fortnite/status', async (c) => {

	let resBody = {
		//@ts-ignore
		"serviceInstanceId": "fortnite",
		"status": "UP",
		"message": "Fortnite is online",
		"maintenanceUri": null,
		"overrideCatalogIds": [
			"a7f138b2e51945ffbfdacc1af0541053"
		],
		"allowedActions": [],
		"banned": false,
		"launcherInfoDTO": {
			"appName": "Fortnite",
			"catalogItemId": "4fe75bbc5a674f4f9b356b5c90567da5",
			"namespace": "fn"
		}
	}

	return c.json(resBody, 200);

});

app.get("/lightswitch/api/service/bulk/status", async (c) => {
	return c.json([{
		"serviceInstanceId": "fortnite",
		"status": "UP",
		"message": "fortnite is up.",
		"maintenanceUri": null,
		"overrideCatalogIds": [
			"a7f138b2e51945ffbfdacc1af0541053"
		],
		"allowedActions": [
			"PLAY",
			"DOWNLOAD"
		],
		"banned": false,
		"launcherInfoDTO": {
			"appName": "Fortnite",
			"catalogItemId": "4fe75bbc5a674f4f9b356b5c90567da5",
			"namespace": "fn"
		}
	}]);
});

//TODO main

app.post('/fortnite/api/game/v2/chat/*/*/*/pc', async (c) => {

	return c.json({ "GlobalChatRooms": [{ "roomName": "Nexus" }] }, 200);

});

app.post('/fortnite/api/game/v2/tryPlayOnPlatform/account/*', async (c) => {

	c.header('Content-Type', 'text/plain');
	return c.text("true");

});

app.get('/launcher/api/public/distributionpoints/', async (c) => {

	return c.json(({
		"distributions": [
			"https://download.epicgames.com/",
			"https://download2.epicgames.com/",
			"https://download3.epicgames.com/",
			"https://download4.epicgames.com/",
			"https://epicgames-download1.akamaized.net/"
		]
	}), 200)

});

app.get('/waitingroom/api/waitingroom/', async (c) => {

	return c.json(204);

});

app.get('/socialban/api/public/v1/*', async (c) => {

	return c.json({
		"bans": [],
		"warnings": []
	}, 200);

});

app.get('/fortnite/api/game/v2/events/tournamentandhistory/*/EU/WindowsClient', async (c) => {

	return c.json({});

});

app.get('/fortnite/api/statsv2/account/:accountId', async (c) => {

	return c.json({
		"startTime": 0,
		"endTime": 0,
		"stats": {},
		"accountId": c.req.param('accountId')
	});

});

app.get('/statsproxy/api/statsv2/account/:accountId', async (c) => {

	return c.json({
		"startTime": 0,
		"endTime": 0,
		"stats": {},
		"accountId": c.req.param('accountId')
	});

});

app.get('/fortnite/api/stats/accountId/:accountId/bulk/window/alltime', async (c) => {

	return c.json({
		"startTime": 0,
		"endTime": 0,
		"stats": {},
		"accountId": c.req.param('accountId')
	});

});

app.post('/fortnite/api/feedback/*', async (c) => {

	return c.json({ "feedback": [] }, 200);

});

app.post('/fortnite/api/statsv2/query', async (c) => {

	return c.json([], 200);

});

app.post('/statsproxy/api/statsv2/query', async (c) => {

	return c.json([], 200);

});

app.post('/fortnite/api/game/v2/events/v2/setSubgroup/*', async (c) => {

	return c.json(204);

});

app.get('/fortnite/api/game/v2/enabled_features', async (c) => {

	return c.json([{}]);

});

app.get('/api/v1/events/Fortnite/download/*', async (c) => {

	return c.json({});

});

app.get('/fortnite/api/game/v2/twitch/*', async (c) => {

	return c.json(204);

})

app.get('/fortnite/api/game/v2/world/info', async (c) => {

	return c.json({});

});

app.post('/fortnite/api/game/v2/chat/*/recommendGeneralChatRooms/pc', async (c) => {

	return c.json({});

});

app.get('/fortnite/api/receipts/v1/account/*/receipts', async (c) => {

	return c.json([]);

});

app.get('/fortnite/api/game/v2/leaderboards/cohort/*', async (c) => {

	c.json([]);

});

app.post('/datarouter/api/v1/public/data/*', async (c) => {

	return c.json(204);

});

//TODO matchmaking

let buildUniqueId: any = {};

app.get('/fortnite/api/matchmaking/session/findPlayer/*', async (c) => {

	return c.json({}, 200);

});

app.get('/fortnite/api/game/v2/matchmaking/ticket/player/*', async (c) => {

	return c.json({
		"serviceUrl": `ws://matchmaker.nexusfn.io`,
		"ticketType": "mms-player",
		"payload": "69=",
		"signature": "420="
	});

});

app.get('/fortnite/api/game/v2/matchmaking/account/:accountId/session/:sessionId', async (c) => {

	return c.json({
		"accountId": c.req.param('accountId'),
		"sessionId": c.req.param('sessionId'),
		"key": "none"
	});

});

app.get('/fortnite/api/matchmaking/session/:sessionId', async (c) => {

	let gameServerInfo = {
		serverAddress: "157.90.174.149",
		serverPort: 7777
	}

	return c.json({
		"id": c.req.param('sessionId'),
		"ownerId": MakeID().replace(/-/ig, "").toUpperCase(),
		"ownerName": "[DS]fortnite-liveeugcec1c2e30ubrcore0a-z8hj-1968",
		"serverName": "[DS]fortnite-liveeugcec1c2e30ubrcore0a-z8hj-1968",
		"serverAddress": gameServerInfo.serverAddress,
		"serverPort": gameServerInfo.serverPort,
		"maxPublicPlayers": 220,
		"openPublicPlayers": 175,
		"maxPrivatePlayers": 0,
		"openPrivatePlayers": 0,
		"attributes": {
			"REGION_s": "EU",
			"GAMEMODE_s": "FORTATHENA",
			"ALLOWBROADCASTING_b": true,
			"SUBREGION_s": "GB",
			"DCID_s": "FORTNITE-LIVEEUGCEC1C2E30UBRCORE0A-14840880",
			"tenant_s": "Fortnite",
			"MATCHMAKINGPOOL_s": "Any",
			"STORMSHIELDDEFENSETYPE_i": 0,
			"HOTFIXVERSION_i": 0,
			"PLAYLISTNAME_s": "Playlist_DefaultSolo",
			"SESSIONKEY_s": MakeID().replace(/-/ig, "").toUpperCase(),
			"TENANT_s": "Fortnite",
			"BEACONPORT_i": 15009
		},
		"publicPlayers": [],
		"privatePlayers": [],
		"totalPlayers": 1,
		"allowJoinInProgress": true,
		"shouldAdvertise": false,
		"isDedicated": false,
		"usesStats": false,
		"allowInvites": false,
		"usesPresence": false,
		"allowJoinViaPresence": true,
		"allowJoinViaPresenceFriendsOnly": false,
		"buildUniqueId": "0",
		"lastUpdated": new Date().toISOString(),
		"started": false
	});

});

app.post('/fortnite/api/matchmaking/session/*/join', async (c) => {

	return c.json(204);

});

app.post('/fortnite/api/matchmaking/session/matchMakingReques', async (c) => {

	return c.json([{}]);

});

//TODO MCP

app.post("/fortnite/api/game/v2/profile/*/client/MarkItemSeen", async (c) => {

	let body: any = c.req.parseBody;

	//@ts-ignore
	const profileId: any = c.req.param("profileId");

	//@ts-ignore
	if (!await profileManager.validateProfile(body.user.accountId, profileId)) return c.json(createError(
		"errors.com.epicgames.modules.profiles.operation_forbidden",
		`Unable to find template configuration for profile ${profileId}`,
		//@ts-ignore
		[profileId], 12813, undefined)
	);
	const foundProfile = await db.getUserAccountID(body.user.accountId);
	console.log(foundProfile);
	const profile = foundProfile[profileId];
	console.log(profile);

	if (profileId == "athena") {
		const memory = functions.GetVersionInfo(c);

		profile.stats.attributes.season_num = memory.season;
	}

	let ApplyProfileChanges: Array<Object> = [];
	let BaseRevision = profile.rvn || 0;
	let QueryRevision = c.req.query("rvn") || -1;
	let StatChanged = false;

	let missingFields: Array<Object> = [];
	if (!body.itemIds) missingFields.push("itemIds");

	if (missingFields.length > 0) return c.json(createError(
		"errors.com.epicgames.validation.validation_failed",
		`Validation Failed. [${missingFields.join(", ")}] field(s) is missing.`,
		[`[${missingFields.join(", ")}]`], 1040, undefined)
	);

	if (!Array.isArray(body.itemIds)) return c.json(createError(
		"errors.com.epicgames.validation.validation_failed",
		`Validation Failed. 'itemIds' is not an array.`,
		["itemIds"], 1040, undefined)
	);

	for (let i in body.itemIds) {
		if (!profile.items[body.itemIds[i]]) continue;

		profile.items[body.itemIds[i]].attributes.item_seen = true;

		ApplyProfileChanges.push({
			"changeType": "itemAttrChanged",
			"itemId": body.itemIds[i],
			"attributeName": "item_seen",
			"attributeValue": true
		});

		StatChanged = true;
	}

	if (StatChanged) {
		profile.rvn += 1;
		profile.commandRevision += 1;
		profile.updated = new Date().toISOString();
	}

	if (QueryRevision != BaseRevision) {
		ApplyProfileChanges = [{
			"changeType": "fullProfileUpdate",
			"profile": profile
		}];
	}

	return c.json({
		profileRevision: profile.rvn || 0,
		profileId: c.req.query("profileId"),
		profileChangesBaseRevision: BaseRevision,
		profileChanges: ApplyProfileChanges,
		profileCommandRevision: profile.commandRevision || 0,
		serverTime: new Date().toISOString(),
		responseVersion: 1
	});

	if (StatChanged) await profiles.updateOne({ $set: { [`profiles.${profileId}`]: profile } });

});



//TODO Reports

app.post('/fortnite/api/game/v2/toxicity/account/:reporter/report/:reportedPlayer', async (c) => {

	const reporter: string = c.req.param('reporter');
	const reportedPlayer: string = c.req.param('reportedPlayer');

	let reporterData: any = await db.getUserAccountID(reporter);
	let reportedPlayerData: any = await db.getUserAccountID(reportedPlayer);

	let reporterDiscordID: string = await reporterData?.discordId;
	let reporterUsername: string = await reporterData?.username;

	let reportedPlayerDiscordID: string = await reportedPlayerData?.discordId;
	let reportedPlayerUsername: string = await reportedPlayerData?.username;
	let reportedPlayerReports: number = parseInt(reportedPlayerData?.reports) || 0;

	const body: any = await c.req.parseBody();

	const reason = await body.reason;
	const details = await body.details;
	const markedAsKnown = await body.bUserMarkedAsKnown ? 'Yes' : 'No';

	console.log(`[REPORT] ${reporterUsername} (${reporter}) reported ${reportedPlayerUsername} (${reportedPlayer}) for ${reason} (${details})`);

	return c.json({ success: true }, 200);

});

app.post("/fortnite/api/game/v2/profile/*/client/SetItemFavoriteStatusBatch", async (c) => {

	let body: any = c.req.parseBody;
	let requser = body.user;

	const profileId = c.req.query("profileId") ?? "";

	if (!await profileManager.validateProfile(requser.accountId, profileId)) return c.json(createError(
		"errors.com.epicgames.modules.profiles.operation_forbidden",
		`Unable to find template configuration for profile ${profileId}`,
		[profileId], 12813, undefined)
	);

	if (profileId != "athena") return c.json(createError(
		"errors.com.epicgames.modules.profiles.invalid_command",
		`SetItemFavoriteStatusBatch is not valid on ${profileId} profile`,
		["SetItemFavoriteStatusBatch", profileId], 12801, undefined)
	);

	const profiles = await db.getProfile(requser.accountId);
	let profile = profiles.profiles[profileId];

	if (profileId == "athena") {
		const memory = functions.GetVersionInfo(c);

		profile.stats.attributes.season_num = memory.season;
	}

	let ApplyProfileChanges: Array<Object> = [];
	let BaseRevision = profile.rvn || 0;
	let QueryRevision = c.req.query("rvn") || -1;
	let StatChanged = false;

	let missingFields: Array<Object> = [];
	if (!body.itemIds) missingFields.push("itemIds");
	if (!body.itemFavStatus) missingFields.push("itemFavStatus");

	if (missingFields.length > 0) return c.json(createError(
		"errors.com.epicgames.validation.validation_failed",
		`Validation Failed. [${missingFields.join(", ")}] field(s) is missing.`,
		[`[${missingFields.join(", ")}]`], 1040, undefined)
	);

	if (!Array.isArray(body.itemIds)) return c.json(createError(
		"errors.com.epicgames.validation.validation_failed",
		`Validation Failed. 'itemIds' is not an array.`,
		["itemIds"], 1040, undefined)
	);

	if (!Array.isArray(body.itemFavStatus)) return c.json(createError(
		"errors.com.epicgames.validation.validation_failed",
		`Validation Failed. 'itemFavStatus' is not an array.`,
		["itemFavStatus"], 1040, undefined)
	);

	for (let i in body.itemIds) {
		if (!profile.items[body.itemIds[i]]) continue;
		if (typeof body.itemFavStatus[i] != "boolean") continue;

		profile.items[body.itemIds[i]].attributes.favorite = body.itemFavStatus[i];

		ApplyProfileChanges.push({
			"changeType": "itemAttrChanged",
			"itemId": body.itemIds[i],
			"attributeName": "favorite",
			"attributeValue": profile.items[body.itemIds[i]].attributes.favorite
		})

		StatChanged = true;
	}

	if (StatChanged) {
		profile.rvn += 1;
		profile.commandRevision += 1;
		profile.updated = new Date().toISOString();
	}

	if (QueryRevision != BaseRevision) {
		ApplyProfileChanges = [{
			"changeType": "fullProfileUpdate",
			"profile": profile
		}];
	}

	return c.json({
		profileRevision: profile.rvn || 0,
		profileId: profileId,
		profileChangesBaseRevision: BaseRevision,
		profileChanges: ApplyProfileChanges,
		profileCommandRevision: profile.commandRevision || 0,
		serverTime: new Date().toISOString(),
		responseVersion: 1
	});

	if (StatChanged) await mongo.updateProfile("accountId", profile, profileId, ATLAS_KEY);

	return;

});

app.post("/fortnite/api/game/v2/profile/*/client/SetBattleRoyaleBanner", async (c) => {

	let body: any = c.req.parseBody;
	let requser = body.user;
	let profileId = c.req.query("profileId") ?? "";

	if (!await profileManager.validateProfile(requser.accountId, profileId)) return c.json(createError(
		"errors.com.epicgames.modules.profiles.operation_forbidden",
		`Unable to find template configuration for profile ${profileId}`,
		[profileId], 12813, undefined)
	);

	if (profileId != "athena") return c.json(createError(
		"errors.com.epicgames.modules.profiles.invalid_command",
		`SetBattleRoyaleBanner is not valid on ${profileId} profile`,
		["SetBattleRoyaleBanner", profileId], 12801, undefined)
	);

	const profiles = await db.getProfile(requser.accountId);
	let profile = profiles.profiles[profileId];

	const memory = functions.GetVersionInfo(c);

	if (profileId == "athena") profile.stats.attributes.season_num = memory.season;

	let ApplyProfileChanges: Array<Object> = [];
	let BaseRevision = profile.rvn || 0;
	let QueryRevision = c.req.query("rvn") || -1;
	let StatChanged = false;

	let missingFields: Array<Object> = [];
	if (!body.homebaseBannerIconId) missingFields.push("homebaseBannerIconId");
	if (!body.homebaseBannerColorId) missingFields.push("homebaseBannerColorId");

	if (missingFields.length > 0) return c.json(createError(
		"errors.com.epicgames.validation.validation_failed",
		`Validation Failed. [${missingFields.join(", ")}] field(s) is missing.`,
		[`[${missingFields.join(", ")}]`], 1040, undefined)
	);

	if (typeof body.homebaseBannerIconId != "string") return c.json(createError(
		"errors.com.epicgames.validation.validation_failed",
		`Validation Failed. 'homebaseBannerIconId' is not a string.`,
		["homebaseBannerIconId"], 1040, undefined)
	);

	if (typeof body.homebaseBannerColorId != "string") return c.json(createError(
		"errors.com.epicgames.validation.validation_failed",
		`Validation Failed. 'homebaseBannerColorId' is not a string.`,
		["homebaseBannerColorId"], 1040, undefined)
	);

	let returnError = true;
	let bannerProfileId = memory.build < 3.5 ? "profile0" : "common_core";

	for (let itemId in profiles.profiles[bannerProfileId].items) {
		if (profiles.profiles[bannerProfileId].items[itemId].templateId.startsWith(`HomebaseBannerIcon:${body.homebaseBannerIconId}`)) returnError = false;
	}

	if (returnError) return c.json(createError(
		"errors.com.epicgames.fortnite.item_not_found",
		`Banner template 'HomebaseBannerIcon:${body.homebaseBannerIconId}' not found in profile`,
		[`HomebaseBannerIcon:${body.homebaseBannerIconId}`], 16006, undefined)
	);

	returnError = true;

	for (let itemId in profiles.profiles[bannerProfileId].items) {
		if (profiles.profiles[bannerProfileId].items[itemId].templateId.startsWith(`HomebaseBannerColor:${body.homebaseBannerColorId}`)) returnError = false;
	}

	if (returnError) return c.json(createError(
		"errors.com.epicgames.fortnite.item_not_found",
		`Banner template 'HomebaseBannerColor:${body.homebaseBannerColorId}' not found in profile`,
		[`HomebaseBannerColor:${body.homebaseBannerColorId}`], 16006, undefined)
	);

	profile.stats.attributes.banner_icon = body.homebaseBannerIconId;
	profile.stats.attributes.banner_color = body.homebaseBannerColorId;

	ApplyProfileChanges.push({
		"changeType": "statModified",
		"name": "banner_icon",
		"value": profile.stats.attributes.banner_icon
	});

	ApplyProfileChanges.push({
		"changeType": "statModified",
		"name": "banner_color",
		"value": profile.stats.attributes.banner_color
	});

	StatChanged = true;

	if (StatChanged) {
		profile.rvn += 1;
		profile.commandRevision += 1;
		profile.updated = new Date().toISOString();
	}

	if (QueryRevision != BaseRevision) {
		ApplyProfileChanges = [{
			"changeType": "fullProfileUpdate",
			"profile": profile
		}];
	}

	return c.json({
		profileRevision: profile.rvn || 0,
		profileId: profileId,
		profileChangesBaseRevision: BaseRevision,
		profileChanges: ApplyProfileChanges,
		profileCommandRevision: profile.commandRevision || 0,
		serverTime: new Date().toISOString(),
		responseVersion: 1
	});

	if (StatChanged) await mongo.updateProfile(requser.accountId, profiles, profileId, ATLAS_KEY);
});

app.post("/fortnite/api/game/v2/profile/*/client/EquipBattleRoyaleCustomization", async (c) => {

	let body: any = c.req.parseBody;
	let requser = body.user;
	let profileId = c.req.query("profileId") || "common_core";

	if (!await profileManager.validateProfile(requser.accountId, profileId)) return c.json(createError(
		"errors.com.epicgames.modules.profiles.operation_forbidden",
		`Unable to find template configuration for profile ${profileId}`,
		[profileId], 12813, undefined)
	);

	if (profileId != "athena") return c.json(createError(
		"errors.com.epicgames.modules.profiles.invalid_command",
		`EquipBattleRoyaleCustomization is not valid on ${profileId} profile`,
		["EquipBattleRoyaleCustomization", profileId], 12801, undefined)
	);

	const profiles = await db.getProfile(requser.accountId);
	let profile = profiles.profiles[profileId];

	if (profileId == "athena") {
		const memory = functions.GetVersionInfo(c);

		profile.stats.attributes.season_num = memory.season;
	}

	let ApplyProfileChanges: Array<Object> = [];
	let BaseRevision = profile.rvn || 0;
	let QueryRevision = c.req.query("rvn") || -1;
	let StatChanged = false;
	let specialCosmetics = [
		"athenacharacter:cid_random",
		"athenabackpack:bid_random",
		"athenapickaxe:pickaxe_random",
		"athenaglider:glider_random",
		"athenaskydivecontrail:trails_random",
		"athenaitemwrap:wrap_random",
		"athenamusicpack:musicpack_random",
		"athenaloadingscreen:lsid_random"
	];

	let missingFields: Array<Object> = [];
	if (!body.slotName) missingFields.push("slotName");

	if (missingFields.length > 0) return c.json(createError(
		"errors.com.epicgames.validation.validation_failed",
		`Validation Failed. [${missingFields.join(", ")}] field(s) is missing.`,
		[`[${missingFields.join(", ")}]`], 1040, undefined)
	);

	if (typeof body.itemToSlot != "string") return c.json(createError(
		"errors.com.epicgames.validation.validation_failed",
		`Validation Failed. 'itemToSlot' is not a string.`,
		["itemToSlot"], 1040, undefined)
	);

	if (typeof body.slotName != "string") return c.json(createError(
		"errors.com.epicgames.validation.validation_failed",
		`Validation Failed. 'slotName' is not a string.`,
		["slotName"], 1040, undefined)
	);

	if (!profile.items[body.itemToSlot] && body.itemToSlot) {
		let item = body.itemToSlot.toLowerCase();

		if (!specialCosmetics.includes(item)) {
			return c.json(createError(
				"errors.com.epicgames.fortnite.id_invalid",
				`Item (id: "${body.itemToSlot}") not found`,
				[body.itemToSlot], 16027, undefined)
			);
		}
	}

	if (profile.items[body.itemToSlot]) {
		if (!profile.items[body.itemToSlot].templateId.startsWith(`Athena${body.slotName}:`)) return c.json(createError(
			"errors.com.epicgames.fortnite.id_invalid",
			`Cannot slot item of type ${profile.items[body.itemToSlot].templateId.split(":")[0]} in slot of category ${body.slotName}`,
			[profile.items[body.itemToSlot].templateId.split(":")[0], body.slotName], 16027, undefined)
		);

		let Variants = body.variantUpdates;
		let item = body.itemToSlot.toLowerCase();

		if (Variants && !specialCosmetics.includes(item)) {
			for (let i in Variants) {
				if (!Variants[i].channel) continue;
				if (!Variants[i].active) continue;

				let index = profile.items[body.itemToSlot].attributes.variants.findIndex((x: { channel: any; }) => x.channel == Variants[i].channel);

				if (index == -1) continue;
				if (!profile.items[body.itemToSlot].attributes.variants[index].owned.includes(Variants[i].active)) continue;

				profile.items[body.itemToSlot].attributes.variants[index].active = Variants[i].active;
			}

			ApplyProfileChanges.push({
				"changeType": "itemAttrChanged",
				"itemId": body.itemToSlot,
				"attributeName": "variants",
				"attributeValue": profile.items[body.itemToSlot].attributes.variants
			})
		}
	}

	let slotNames = ["Character", "Backpack", "Pickaxe", "Glider", "SkyDiveContrail", "MusicPack", "LoadingScreen"];

	switch (body.slotName) {
		case "Dance":
			var indexwithinslot = body.indexWithinSlot || 0;

			if (indexwithinslot >= 0 && indexwithinslot <= 5) {
				profile.stats.attributes.favorite_dance[indexwithinslot] = body.itemToSlot || "";

				StatChanged = true;
			}
			break;

		case "ItemWrap":
			var indexwithinslot = body.indexWithinSlot || 0;

			switch (true) {
				case indexwithinslot >= 0 && indexwithinslot <= 7:
					profile.stats.attributes.favorite_itemwraps[indexwithinslot] = body.itemToSlot || "";
					StatChanged = true;
					break;

				case indexwithinslot == -1:
					for (var i = 0; i < 7; i++) {
						profile.stats.attributes.favorite_itemwraps[i] = body.itemToSlot || "";
					}
					StatChanged = true;
					break;
			}
			break;

		default:
			if (!slotNames.includes(body.slotName)) break;
			let Category = (`favorite_${body.slotName}`).toLowerCase();

			profile.stats.attributes[Category] = body.itemToSlot || "";
			StatChanged = true;
			break;
	}

	if (StatChanged) {
		let Category = (`favorite_${body.slotName}`).toLowerCase();
		if (Category == "favorite_itemwrap") Category += "s";

		profile.rvn += 1;
		profile.commandRevision += 1;
		profile.updated = new Date().toISOString();

		ApplyProfileChanges.push({
			"changeType": "statModified",
			"name": Category,
			"value": profile.stats.attributes[Category]
		});
	}

	if (QueryRevision != BaseRevision) {
		ApplyProfileChanges = [{
			"changeType": "fullProfileUpdate",
			"profile": profile
		}];
	}

	return c.json({
		profileRevision: profile.rvn || 0,
		profileId: profileId,
		profileChangesBaseRevision: BaseRevision,
		profileChanges: ApplyProfileChanges,
		profileCommandRevision: profile.commandRevision || 0,
		serverTime: new Date().toISOString(),
		responseVersion: 1,
	});

	if (StatChanged) await mongo.updateProfile(requser.accountId, profile, profileId, ATLAS_KEY);
});

app.get("/profiletest/", async (c) => {

	const profiles = JSON.parse(await c.env.CACHE.get(`profile_63167735267d4edf860e29eb79174690`));

	let profile = profiles;

	c.header('Content-Type', 'application/json');
	return c.json(profile);

});

app.post("/fortnite/api/game/v2/profile/*/client/:operation", async (c) => {

	let body: any = c.req.parseBody();
	let requser = body.user;
	let profileId = c.req.query("profileId") || "common_core";
	const accountId = "63167735267d4edf860e29eb79174690"

	if (!await profileManager.validateProfile(accountId, profileId)) return c.json(createError(
		"errors.com.epicgames.modules.profiles.operation_forbidden",
		`Unable to find template configuration for profile ${profileId}`,
		[profileId], 12813, undefined)
	);

	const profiles = await db.getProfile("accountId");
	let profile = profiles.profiles[profileId];

	if (profileId == "athena") {
		const memory = functions.GetVersionInfo(c);

		profile.stats.attributes.season_num = memory.season;
	}

	let ApplyProfileChanges: Array<Object> = [];
	let BaseRevision = profile.rvn || 0;
	let QueryRevision = c.req.query("rvn") || -1;

	switch (c.req.param("operation")) {
		case "QueryProfile":
			break;
		case "ClientQuestLogin":
			break;
		case "RefreshExpeditions":
			break;
		case "GetMcpTimeForLogin":
			break;
		case "IncrementNamedCounterStat":
			break;
		case "SetHardcoreModifier":
			break;
		case "SetMtxPlatform":
			break;
		case "SetAffiliateName": {
			break;
		}
		case "RemoveGiftBox":
			break;
		case "SetReceiveGiftsEnabled": {
			break;
		}

		default:
			return c.json(createError(
				"errors.com.epicgames.fortnite.operation_not_found",
				`Operation ${c.req.param("operation")} not valid`,
				[c.req.param("operation")], 16035, undefined)
			);
	}

	if (QueryRevision != BaseRevision) {
		ApplyProfileChanges = [{
			"changeType": "fullProfileUpdate",
			"profile": profile
		}];
	}

	return c.json({
		profileRevision: profile.rvn || 0,
		profileId: profileId,
		profileChangesBaseRevision: BaseRevision,
		profileChanges: ApplyProfileChanges,
		profileCommandRevision: profile.commandRevision || 0,
		serverTime: new Date().toISOString(),
		responseVersion: 1
	});
});

//TODO Timeline

app.get('/fortnite/api/calendar/v1/timeline', async (c) => {

	const memory = functions.GetVersionInfo(c)

	let activeEvents = [
		{
			"eventType": `EventFlag.Season${memory.season}`,
			"activeUntil": "9999-01-01T00:00:00.000Z",
			"activeSince": "2020-01-01T00:00:00.000Z"
		},
		{
			"eventType": `EventFlag.${memory.lobby}`,
			"activeUntil": "9999-01-01T00:00:00.000Z",
			"activeSince": "2020-01-01T00:00:00.000Z"
		}
	];

	return c.json({
		channels: {
			"client-matchmaking": {
				states: [],
				cacheExpire: "9999-01-01T00:00:00.000Z"
			},
			"client-events": {
				states: [{
					validFrom: "0001-01-01T00:00:00.000Z",
					activeEvents: activeEvents,
					state: {
						activeStorefronts: [],
						eventNamedWeights: {},
						seasonNumber: memory.season,
						seasonTemplateId: `AthenaSeason:athenaseason${memory.season}`,
						matchXpBonusPoints: 0,
						seasonBegin: "2020-01-01T00:00:00Z",
						seasonEnd: "9999-01-01T00:00:00Z",
						seasonDisplayedEnd: "2023-04-30T00:00:00Z",
						weeklyStoreEnd: "9999-01-01T00:00:00Z",
						stwEventStoreEnd: "9999-01-01T00:00:00.000Z",
						stwWeeklyStoreEnd: "9999-01-01T00:00:00.000Z",
						dailyStoreEnd: "2023-05-30T00:00:00Z"
					}
				}],
				cacheExpire: "9999-01-01T00:00:00.000Z"
			}
		},
		eventsTimeOffsetHrs: 0,
		cacheIntervalMins: 10,
		currentTime: new Date().toISOString()
	}, 200);
});

//TODO User

app.get("/account/api/public/account", async (c) => {

	let response: Array<Object> = [];

	if (typeof c.req.query("accountId") == "string") {
		let user = await db.getUserAccountID(c.req.query("accountId") || "")


		if (user) {
			response.push({
				id: user.accountid,
				displayName: user.username,
				externalAuths: {}
			});
		}
	}

	if (Array.isArray(c.req.query("accountId"))) {
		let users = await db.getUserAccountID(c.req.query("accountId") || "")

		if (users) {
			for (let user of users) {
				response.push({
					id: user.accountid,
					displayName: user.username,
					externalAuths: {}
				});
			}
		}
	}

	return c.json(response, 200);

});

app.get("/account/api/public/account/displayName/:displayName", async (c) => {

	let user = await db.getUserUsername(c.req.param("displayName"))
	console.log(user)

	if (!user) return c.json(createError(
		"errors.com.epicgames.account.account_not_found",
		`Sorry, we couldn't find an account for ${c.req.param("displayName")}`,
		[c.req.param('displayName')], 18007, undefined)
	);

	return c.json({
		id: user.accountid,
		displayName: user.username,
		externalAuths: {}
	});

});

app.get("/account/api/public/account/:accountId", async (c) => {

	let user = await db.getUserAccountID(c.req.param("accountId"))

	return c.json({
		id: user.accountid,
		displayName: user.username,
		name: "Account",
		email: `[redacted]@${user.email.split("@")[1]}`,
		failedLoginAttempts: 0,
		lastLogin: new Date().toISOString(),
		numberOfDisplayNameChanges: 0,
		ageGroup: "UNKNOWN",
		headless: false,
		country: "US",
		lastName: "Server",
		preferredLanguage: "en",
		canUpdateDisplayName: false,
		tfaEnabled: false,
		emailVerified: true,
		minorVerified: false,
		minorExpected: false,
		minorStatus: "UNKNOWN"
	});

});

app.get("/account/api/public/account/*/externalAuths", async (c) => {
	return c.json([{}]);
});

//TODO Version

app.get("/fortnite/api/version", async (c) => {

	return c.json({
		"app": "fortnite",
		"serverDate": new Date().toISOString(),
		"overridePropertiesVersion": "unknown",
		"cln": "17951730",
		"build": "444",
		"moduleName": "Fortnite-Core",
		"buildDate": "2021-10-27T21:00:51.697Z",
		"version": "18.30",
		"branch": "Release-18.30",
		"modules": {
			"Epic-LightSwitch-AccessControlCore": {
				"cln": "17237679",
				"build": "b2130",
				"buildDate": "2021-08-19T18:56:08.144Z",
				"version": "1.0.0",
				"branch": "trunk"
			},
			"epic-xmpp-api-v1-base": {
				"cln": "5131a23c1470acbd9c94fae695ef7d899c1a41d6",
				"build": "b3595",
				"buildDate": "2019-07-30T09:11:06.587Z",
				"version": "0.0.1",
				"branch": "master"
			},
			"epic-common-core": {
				"cln": "17909521",
				"build": "3217",
				"buildDate": "2021-10-25T18:41:12.486Z",
				"version": "3.0",
				"branch": "TRUNK"
			}
		}
	});
});

app.get("/fortnite/api*/versioncheck*", async (c) => {
	return c.json({
		"type": "NO_UPDATE"
	});
});

//TODO Storefront

app.get("/fortnite/api/storefront/v2/catalog", async (c) => {

	//@ts-ignore
	if (c.req.header("user-agent").includes("2870186")) return c.json({}, 204);

	//@ts-ignore
	const cachedShop = await c.env.CACHE.get("shop");
	if (cachedShop) {
		console.log('Found shop in cache')
		const parsedShop = JSON.parse(cachedShop);
		return c.json({
			parsedShop,
		})
	} else {
		console.log('Shop not found in cache')

		return c.json({
			"error": "Not Found",
		}, 200);
	}

})

app.get("/fortnite/api/storefront/v2/keychain", async (c) => {

	//@ts-ignore
	const cachedKeychain: string = await c.env.CACHE.get("keychain");
	if (cachedKeychain) {
		const parsedKeychain = JSON.parse(cachedKeychain);
		//set content type to json
		c.req.header("content-type: application/json");
		return c.text(
			parsedKeychain,
		)
	} else {
		return c.json({
			"error": "Not Found",
		}, 200);
	}

});

//TODO Eos
app.patch('/epic/presence/v1/:gameNsIg/:accountId/presence/:presenceUuid', async (c) => {
	return c.json({
		"own": {
			"accountId": c.req.param("accountId"),
			"status": "online",
			"perNs": []
		}
	});
});

//TODO Modt

app.get("/content/api/pages/fortnite-game", async (c) => { });

export default app
