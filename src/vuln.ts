import * as utils from './utils'
import * as filterset from './filterset'
import * as core from '@actions/core'


export async function getAppVersionVulnsCount(appId: number | string, filterSet: string, analysisType?: String, newIssues?: boolean): Promise<any> {
    let query = ""
    if (newIssues) {
        query = "[issue age]:NEW"
    }
    core.debug(query)
    const url = `/api/v1/projectVersions/${appId}/issueGroups?filterset=${await filterset.getFilterSetGuid(appId, filterSet)}&groupingtype=FOLDER${query.length ? `&qm=issues&q=${encodeURI(query)}` : ""}`
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
        return jsonRes[0].data
    } else {
        throw new Error(`issueSummaries failed with code ${responseCode}`)
    }
}


export async function getAppVersionNewVulnsCount(appId: number | string, filterSet: string, analysisType?: String): Promise<any> {
    return await getAppVersionVulnsCount(appId, filterSet, analysisType, true)
}

export async function getAppVersionVulnsCountTotal(appId: number | string, filterSet: string, analysisType?: String, newIssues: boolean = false): Promise<any> {
    const count: any[] = await getAppVersionVulnsCount(appId, filterSet, analysisType, newIssues)
    let total: number = 0
    count.forEach(item => {
        total += item["totalCount"]
    })

    return total
}
