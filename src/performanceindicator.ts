import * as utils from "./utils";
import * as core from "@actions/core";
import * as filterset from "./filterset";


export async function getPerformanceIndicatorByName(
    appId: string|number,
    performanceIndicatorName: string): Promise<any> {

    const url = `/api/v1/projectVersions/${appId}/performanceIndicatorHistories?q=name:${encodeURI(performanceIndicatorName)}`
    core.debug(url)

    return await utils.fcliRest(url)
}

export async function getPerformanceIndicatorValueByName(
    appId: string|number,
    performanceIndicatorName: string): Promise<number> {
    let jsonRes = await getPerformanceIndicatorByName(appId, performanceIndicatorName)

    return parseFloat(jsonRes["value"])
    }
