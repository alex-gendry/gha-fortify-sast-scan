import * as vuln from "./vuln";
import * as appversion from "./appversion";

export async function run(INPUT: any): Promise<boolean> {
    const appId = await appversion.getAppVersionId(INPUT.app, INPUT.version)
    const count = await vuln.getAppVersionVulnsCountTotal(appId, INPUT.security_gate_filterset)

    const status: boolean = count ? false : true

    return status
}