//@ts-ignore
import { JSONRequest } from "@worker-tools/shed";

class mongo {

    getUser = async (key:string, value:string, ATLAS_KEY:string) => {

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
				key: value
			}
		}
	})).then(res => res.json());

        return response.document;

    }

    getFriends = async (key:string, value:string, ATLAS_KEY:string) => {

        const response: any = await fetch(new JSONRequest('https://data.mongodb-api.com/app/data-tsmsh/endpoint/data/beta/action/findOne', {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			'apiKey': ATLAS_KEY
		},
		body: {
			"dataSource": "Nexus",
			"database": "Serverless",
			"collection": "friends",
			"filter": {
				key: value
			}
		}
	})).then(res => res.json());

        return response.document;

    }

}

export default new mongo();