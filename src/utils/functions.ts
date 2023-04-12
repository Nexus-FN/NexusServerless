import { Context } from "hono";

class functions {

    GetVersionInfo(c:Context) {
        let memory = {
            season: 0,
            build: 0.0,
            CL: "0",
            lobby: ""
        }
    
        if (c.req.header("user-agent")) {
            let CL = "";
    
            try {
                //@ts-ignore
                let BuildID = c.req.header("user-agent").split("-")[3].split(",")[0];
    
                if (!Number.isNaN(Number(BuildID))) CL = BuildID;
                else {
                    //@ts-ignore
                    BuildID = c.req.header("user-agent").split("-")[3].split(" ")[0];
    
                    if (!Number.isNaN(Number(BuildID))) CL = BuildID;
                    }
            } catch {
                try {
                    //@ts-ignore
                    let BuildID = c.req.header("user-agent").split("-")[1].split("+")[0];
    
                    if (!Number.isNaN(Number(BuildID))) CL = BuildID;
                } catch {}
            }
    
            try {
                //@ts-ignore
                let Build = c.req.header("user-agent").split("Release-")[1].split("-")[0];
    
                if (Build.split(".").length == 3) {
                    let Value = Build.split(".");
                    Build = Value[0] + "." + Value[1] + Value[2];
                }
    
                memory.season = Number(Build.split(".")[0]);
                memory.build = Number(Build);
                memory.CL = CL;
                memory.lobby = `LobbySeason${memory.season}`;
    
                if (Number.isNaN(memory.season)) throw new Error();
            } catch {
                if (Number(memory.CL) < 3724489) {
                    memory.season = 0;
                    memory.build = 0.0;
                    memory.CL = CL;
                    memory.lobby = "LobbySeason0";
                } else if (Number(memory.CL) <= 3790078) {
                    memory.season = 1;
                    memory.build = 1.0;
                    memory.CL = CL;
                    memory.lobby = "LobbySeason1";
                } else {
                memory.season = 2;
                memory.build = 2.0;
                memory.CL = CL;
                memory.lobby = "LobbyWinterDecor";
            }
        }
    }
    
        return memory;
    }

}

export default new functions();