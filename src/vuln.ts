import * as utils from './utils'
import * as filterset from './filterset'
import * as core from '@actions/core'


export async function getAppVersionVulnsCount(appId: number | string, filterSet: string, analysisType?: String, newIssues?: boolean): Promise<any> {
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
            default:
                query = `${query}${query.length ? " AND " : ""}[analysis type]:${analysisType}`
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

export async function getNewVulnByScanId(appId: number | string, scanId: number | string): Promise<any> {
    let vulns: any[] = []
    const query: string = `[issue age]:NEW AND [analysis type]:"sca"`
    let next: boolean = true
    let url: string = `/api/v1/projectVersions/${appId}/issues?q=${encodeURI(query)}&qm=issues&fields=id,revision,lastScanId`

    while (next) {
        core.debug(`url: ${url}`)
        let {data: data, count: count, responseCode: responseCode, links: links} = await utils.fcliRest(url)
        core.debug(`responseCode ${responseCode}`)

        if (200 <= Number(responseCode) && Number(responseCode) < 300) {
            var jp = require('jsonpath')
            vulns = vulns.concat(jp.query(data, `$..[?(@.lastScanId=="${scanId}")]`))

            if (links.next) {
                next = true
                url = links.next.href.replace(core.getInput("ssc_base_url"), "")
            } else {
                next = false
            }
        } else {
            throw new Error(`getNewVulnByScanId failed with code ${responseCode}`)
        }
    }

    return vulns
}

export async function getFileNewVulnsInDiffHunk(appId: number | string, file: string, diffHunk: any, fields?: string): Promise<any[]> {
    let vulns: any[] = []

    const query: string = `[analysis type]:"sca" AND file:"${file}" AND line:[${diffHunk.start},${diffHunk.end}]`

    core.debug(`query: ${query}`)
    const url: string = `/api/v1/projectVersions/${appId}/issues?q=${encodeURI(query)}&qm=issues${fields ? `&fields=${fields}` : ""}`
    core.debug(`url: ${url}`)
    let {data: data, count: count, responseCode: responseCode, links: links} = await utils.fcliRest(url)
    core.debug(`responseCode ${responseCode}`)

    if (200 <= Number(responseCode) && Number(responseCode) < 300) {
        return data
    } else {
        throw new Error(`getFileNewVulnsInDiffHunk failed with code ${responseCode}`)
    }
}

export async function addDetails(vulns: any[], fields?: string): Promise<void> {
    await Promise.all(
        vulns.map(async vuln => {
            const url = `/api/v1/issueDetails/${vuln.id}`
            core.debug(`url: ${url}`)
            let {data: data, count: count, responseCode: responseCode, links: links} = await utils.fcliRest(url)
            core.debug(`responseCode ${responseCode}`)

            if (200 <= Number(responseCode) && Number(responseCode) < 300) {
                if (fields) {
                    vuln.details = {}
                    fields.split(",").forEach(field => {
                        vuln.details[field] = data[field]
                    })
                } else {
                    vuln.details = data
                }
            } else {
                core.warning(`addDetails failed with code ${responseCode} for vuln ${vuln.id}`)
            }

        })
    )
}

export async function tagVulns(appId: string | number, vulns: any[], guid: string, value: string): Promise<boolean> {
    let body: any = {
        "customTagAudit": {
            "customTagGuid": guid,
            "textValue": value
        },
        "issues": vulns
    }

    core.debug(body)
    let {
        data: data,
        count: count,
        responseCode: responseCode,
        links: links
    } = await utils.fcliRest(`/api/v1/projectVersions/${appId}/issues/action/updateTag`, "POST", JSON.stringify(body))
    core.debug(responseCode)

    if (200 <= Number(responseCode) && Number(responseCode) < 300) {
        return true
    } else {
        core.error(`AppVersion Commit failed with code ${responseCode}`)
        return false
    }

    return true
}