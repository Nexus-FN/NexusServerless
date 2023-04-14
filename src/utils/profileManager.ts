import mongo from "./mongo";

class profileManager {

    async validateProfile(accountId:string, profileId:string) {
        try {

            console.log(accountId + " is accountId");

            let foundProfile = JSON.parse(await c.env.CACHE.get(`profile_${accountId}`));
            console.log(foundProfile + " is profile");
    
            if (!foundProfile || !profileId) throw new Error("Invalid profile/profileId");
        } catch {
            return false;
        }
    
        return true;
    }

    async createProfile(accountId:string, c:any) {
        
            const profiles:{} = c.env.CACHE.get('profilestemplate');

            const profile = {
                accountId: accountId,
                created: Date.now(),
                updated: Date.now(),
                profiles: profiles
            };
        
            return profile;
    }

}

export default new profileManager();