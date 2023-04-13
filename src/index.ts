import { Hono } from 'hono'

const app = new Hono()

//@ts-ignore
import { JSONRequest } from '@worker-tools/json-fetch';
import jwt from '@tsndr/cloudflare-worker-jwt';
import { cache } from 'hono/cache'
import { prettyJSON } from 'hono/pretty-json'
import mongo from './utils/mongo'
import functions from './utils/functions'
import { uuid } from '@cfworker/uuid';

const JWT_SECRET: string = 'nexus';
const ATLAS_KEY: string = 's0iJyjBYCH004YlzTvxvgtJEHeYtx5VucAZLUgJHUlSSVj4WZC8NsfsjhJAjXPo0'

const clientTokens: any[] = [];
const refreshTokens: any[] = [];
const accessTokens: any[] = [];

const Clients: any[] = [];

const exchangeTokens = [];

interface Env {
	NXBUCKET: R2Bucket
	TOKENS: KVNamespace
}

//Functions

function createAccess(user: any, clientId: string, grant_type: string, deviceId: string, expiresIn: any) {

	let accessToken = jwt.sign({
		"app": "fortnite",
		"sub": user.accountId,
		"dvid": deviceId,
		"mver": false,
		"clid": clientId,
		"dn": user.username,
		"am": grant_type,
		"p": btoa(uuid()),
		"iai": user.accountId,
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

app.use('*', prettyJSON()) // With options: prettyJSON({ space: 4 })

app.use('*', async (c, next) => {

	const start = Date.now();
	await next();
	const end = Date.now();
	c.res.headers.set('X-Response-Time', `${end - start}ms`);

});

app.get(
	'*',
	cache({
		cacheName: 'nexuscache',
		cacheControl: 'max-age=3600',
	})
)

app.get('/health', (c) => {
	return c.json({
		status: 'ok',
	})
})

app.get('/vaultmp', async (c) => {

	const shouldWork:boolean = c.env.TOKENS.get('shouldWork');
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
						"email": email.toLowerCase(),
					}
				}
			})).then(res => res.json());

			requser = await response.document;

			console.log(requser);

			error = createError(
				"errors.com.epicgames.account.invalid_account_credentials",
				"Your e-mail and/or password are incorrect. Please check them and try again.",
				[], 18031, "invalid_grant"
			);

			console.log("oauth: email: " + email);
			console.log("oauth: password: " + password);

				if (requser.password !== body.password) {
					console.log("oauth: error created: email or password incorrect");
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
			const rtResponse: any = await fetch(new JSONRequest('https://data.mongodb-api.com/app/data-tsmsh/endpoint/data/beta/action/findOne', {
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
						"accountId": object.accountId,
					}
				}
			})).then(res => res.json());

			requser = rtResponse.document;

			break;

		default:
			error = createError(
				"errors.com.epicgames.common.oauth.unsupported_grant_type",
				`Unsupported grant type: ${body.grant_type}`,
				[], 1016, "unsupported_grant_type")
				console.log("oauth: unsupported grant type");
			return c.json(error, 400);
	}

	if (requser.banned || false) {
		console.log("oauth: account banned step");
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
		"account_id": requser.accountId,
		"client_id": clientId,
		"internal_client": true,
		"client_service": "fortnite",
		"displayName": requser.username,
		"app": "fortnite",
		"in_app_id": requser.accountId,
		"device_id": deviceId
	}

	console.log("oauth: return body created");

	return c.json(returnBody, 200);

});

app.post('/account/api/oauth/exchange', async (c) => {

	let resBody = {
		//@ts-ignore
		"errorCode": "errors.com.epicgames.common.oauth.invalid_request",
		"errorMessage": "This endpoint is not supported.",
		"messageVars": [],
		"numericErrorCode": 1013,
		"originatingService": "account",
		"intent": "prod"
	}

	return c.json(resBody, 400);

});

app.delete('/account/api/oauth/sessions/kill', async (c) => {

	return c.json({});

});

app.delete('/account/api/oauth/sessions/kill/:token', async (c) => {

	let token = c.req.param('token');

	let accessIndex = accessTokens.findIndex(i => i.token == token);

	if (accessIndex != -1) {
		let object = accessTokens[accessIndex];

		accessTokens.splice(accessIndex, 1);

		let xmppClient = Clients.find(i => i.token == object.token);
		if (xmppClient) xmppClient.client.close();

		let refreshIndex = refreshTokens.findIndex(i => i.accountId == object.accountId);
		if (refreshIndex != -1) refreshTokens.splice(refreshIndex, 1);

		let clientIndex = clientTokens.findIndex(i => i.token == token);
		if (clientIndex != -1) clientTokens.splice(clientIndex, 1);

		return c.json({}, 200);

	}

});

//Cloud storage

app.get('/fortnite/api/cloudstorage/system', async (c) => {

	const CloudFiles: Array<Object> = [];

	try {



	} catch {

	}

	return c.json(CloudFiles, 200);

});

//TODO Contentpages

app.get('/content/api/pages/*', async (c) => {

	return c.json({});

});

//TODO Friends

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

//TODO main

app.get('/fortnite/api/game/v2/chat/*/*/*/pc', async (c) => {

	return c.json({ "GlobalChatRooms": [{ "roomName": "Nexus" }] }, 200);

});

app.get('/fortnite/api/game/v2/tryPlayOnPlatform/account/*', async (c) => {

	c.header('Content-Type', 'application/json');
	return c.json(true, 200);

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

app.get('/waitingroom/api/waitingroom', async (c) => {

	return c.json({ "status": "OK" }, 200);

});

app.get('/socialban/api/public/v1/*', async (c) => {

	return c.json({
		"bans": [],
		"warnings": []
	}, 200);

});

app.get('/fortnite/api/game/v2/events/tournamentandhistory/*/EU/WindowsClient', async (c) => {

	return c.json({ "events": [] }, 200);

});

app.get('/fortnite/api/statsv2/account/:accountId', async (c) => {

	return c.json({
		"startTime": 0,
		"endTime": 0,
		"stats": {},
		"accountId": c.req.param('accountId')
	}, 200);

});

app.get('/statsproxy/api/statsv2/account/:accountId', async (c) => {

	return c.json({
		"startTime": 0,
		"endTime": 0,
		"stats": {},
		"accountId": c.req.param('accountId')
	}, 200);

});

app.get('/fortnite/api/stats/accountId/:accountId/bulk/window/alltime', async (c) => {

	return c.json({
		"startTime": 0,
		"endTime": 0,
		"stats": {},
		"accountId": c.req.param('accountId')
	}, 200);

});

app.get('/fortnite/api/feedback/*', async (c) => {

	return c.json({ "feedback": [] }, 200);

});

app.get('/fortnite/api/statsv2/query', async (c) => {

	c.json([], 200);

});

app.get('/statsproxy/api/statsv2/query', async (c) => {

	return c.json([], 200);

});

app.get('/fortnite/api/game/v2/events/v2/setSubgroup/*', async (c) => {

	return c.json({}, 200);

});

app.get('/fortnite/api/game/v2/enabled_features', async (c) => {

	return c.json({}, 200);

});

app.get('/api/v1/events/Fortnite/download/*', async (c) => {

	return c.json({}, 200);

});

app.get('/fortnite/api/game/v2/twitch/*', async (c) => {

	return c.json({}, 200);

})

app.get('/fortnite/api/game/v2/world/info', async (c) => {

	return c.json({}, 200);

});

app.get('/fortnite/api/game/v2/chat/*/recommendGeneralChatRooms/pc', async (c) => {

	return c.json(200, {});

});

app.get('/fortnite/api/receipts/v1/account/*/receipts', async (c) => {

	c.json([], 200);

});

app.get('/fortnite/api/game/v2/leaderboards/cohort/*', async (c) => {

	c.json([], 200);

});

app.post('/datarouter/api/v1/public/data/*', async (c) => {

	return c.json({}, 200);

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

	c.status(200);

});

app.post('/fortnite/api/matchmaking/session/matchMakingReques', async (c) => {

	c.json([]);

});

//TODO MCP

//TODO Reports

app.post('/fortnite/api/game/v2/toxicity/account/:reporter/report/:reportedPlayer', async (c) => {

	const reporter: string = c.req.param('reporter');
	const reportedPlayer: string = c.req.param('reportedPlayer');

	let reporterData: any = await mongo.getUser("accountId", reporter, ATLAS_KEY);
	let reportedPlayerData: any = await mongo.getUser("accountId", reportedPlayer, ATLAS_KEY);

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

//TODO Version

//TODO Storefront

app.get("/fortnite/api/storefront/v2/catalog", async (c) => {

	//@ts-ignore
	if (c.req.header("user-agent").includes("2870186")) return c.status(404);

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
		const parsedKeychain: JSON = JSON.parse(cachedKeychain);
		return c.json({
			parsedKeychain,
		})
	} else {
		return c.json({
			"error": "Not Found",
		}, 200);
	}

});

export default app
