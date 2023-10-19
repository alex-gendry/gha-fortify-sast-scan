import * as vuln from "./vuln";
import * as appversion from "./appversion";
import * as core from "@actions/core";

export async function run(INPUT: any): Promise<boolean> {
    const appId = await appversion.getAppVersionId(INPUT.ssc_app, INPUT.ssc_version)
    const count = await vuln.getAppVersionVulnsCountTotal(appId, INPUT.security_gate_filterset)

    const passed: boolean = count ? false : true

    if (!passed) {
        switch (INPUT.security_gate_action.toLowerCase()) {
            case 'warn':
                core.info("Security Gate has been set to Warning only")
                core.warning('Security Gate Failure')
                break
            case 'block':
                core.info("Security Gate has been set to Blocking. The job will fail")
                core.setFailed('Security Gate Failure')
                break
        }
    }

    return passed
}