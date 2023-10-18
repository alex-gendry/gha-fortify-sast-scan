import * as utils from "./utils";
import * as core from "@actions/core";
import * as filterset from "./filterset";


async function getPerformanceIndicatorByName(
    appId: string|number,
    performanceIndicatorName: string): Promise<any> {

    const url = `/api/v1/projectVersions/${appId}/performanceIndicatorHistories?q=name:"${performanceIndicatorName}"`
    core.debug(url)
    let jsonRes = await utils.fcli([
        'ssc',
        'rest',
        'call',
        url,
        '--output=json'
    ])
    const responseCode = jsonRes[0].responseCode
    core.debug(responseCode)

    if (200 <= Number(responseCode) && Number(responseCode) < 300) {
        return jsonRes[0].data[0]
    } else {
        throw new Error(`GET performanceIndicatorHistories failed with code ${responseCode}`)
    }
}
