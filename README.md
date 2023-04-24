# Nexus Serverless

<img src="https://camo.githubusercontent.com/3cfa16e48affed3aa466ef01e32b1a5089816ca4dd4e6de5d30cda7238ef9ba8/68747470733a2f2f692e696d6775722e636f6d2f3938614f68627a2e706e67"/>

[![License: SSPL v1](https://img.shields.io/badge/License-SSPL%20v1-blue.svg)](https://www.mongodb.com/licensing/server-side-public-license)
[![GitHub issues](https://img.shields.io/github/issues/SkynetFN/NexusHono)](https://github.com/SkynetFN/NexusHono/issues)
[![GitHub stars](https://img.shields.io/github/stars/SkynetFN/NexusHono)](https://github.com/SkynetFN/NexusHono/stargazers)

https://discord.gg/dpKesqXuEz

Nexus Serverless is a serverless backend based on the popular Fortnite backend "LawinServerV2", modified to work with Cloudflare workers. It's currently in [![Version - ALPHA](https://img.shields.io/badge/Version-ALPHA-ed3939)](https://) and not suitable for production usage. Why would you use this over normal Lawin? Well, edge functions have the advantage of always executing near the user who is requesting the route. This can be combined well with edge databases or D1 if you're using Cloudflare workers. I am planning to fully switch to D1 as it has the benefits of great performance and costing next to nothing.

Todo:

- Fix random logout errors (99% because of local token storage as it's a worker and can't have consistent variables to store the array of tokens)
- Fix it being slow as fuck

If you can help fix these issues, please message me on Discord or just create a pull request

## License

The project is licensed under the SSPL (Server Side Public License) v1, created by MongoDB. It requires any software that uses the licensed software to make its complete source code available to users of the software as a service. This means that if you use SSPL-licensed software to provide a service, you must release the source code of your service under the SSPL.

You can find the full text of the SSPL v1 license in the `LICENSE` file in this project.

## Contributing

We welcome contributions from everyone! If you have suggestions for how to improve Nexus Serverless, please open an issue or a pull request.

Please note that we have a code of conduct, and that all activity in the Nexus Serverless project is governed by it. Please read the [code of conduct](CODE_OF_CONDUCT.md) before contributing.
## Getting Started

To get started with Nexus Serverless, please follow the instructions in the [README](https://github.com/NexusFN-io/NexusServerless/blob/main/SETUP.md) file in this project.


