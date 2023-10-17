import * as utils from './utils'
import * as filterset from './filterset'
import * as core from '@actions/core'


export async function getAppVersionVulnsCount(appId: number | string, filterSet:string, analysisType?: String, newIssues?: boolean): Promise<any> {
    let query = ""
    if (newIssues) {
        query = "[issue age]:NEW"
    }
    if (analysisType) {
        switch (analysisType) {
            case "SAST":
                query = `${query}${query.length ? " AND " : ""}[analysis type]:SCA`
                break
            case "DAST":
                query = `${query}${query.length ? " AND " : ""}[analysis type]:WEBINSPECT`
                break
            case "SCA":
                query = `${query}${query.length ? " AND " : ""}[analysis type]:SONATYPE`
                break
        }
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
