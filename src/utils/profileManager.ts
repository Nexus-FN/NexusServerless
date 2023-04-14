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

}

export default new profileManager();