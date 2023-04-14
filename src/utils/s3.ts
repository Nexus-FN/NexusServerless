import { Context } from "hono";

class s3 {

    getCloudFile = async (objectName: string, c: Context) => {
        try {
            const file = await c.env.NXBUCKET.get(objectName);
            return file;
        } catch (err: any) {
            if (err.code === "NoSuchKey") {
                throw new Error("File not found");
            }
            throw err;
        }
    };

    listFiles = async (c: Context, prefix:string) => {

        const options: R2ListOptions = {
            prefix: prefix ?? "",
        }

        const files = await c.env.NXBUCKET.list(options)
        console.log(files)
        return files;
    };

}

export default new s3();