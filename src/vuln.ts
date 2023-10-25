import * as utils from './utils'
import * as filterset from './filterset'
import * as core from '@actions/core'
import * as querystring from "querystring";


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

    return await utils.fcliRest(url)
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

export async function getVulnsByScanId(appVersionId: number | string, scanId: number | string): Promise<any> {
    return await getAppVersionVulns(appVersionId, "", `lastScanId==${scanId}`, "id,revision")
}

export async function getAppVersionVulns(appId: number | string, restQuery?: string, fcliQuery?: string, fields?: string, embed?: string): Promise<any[]> {
    let vulns: any[] = []

    let url: string = `/api/v1/projectVersions/${appId}/issues?`
    url += restQuery ? `q=${encodeURI(restQuery)}&qm=issues&` : ""
    url += fields ? `fields=${fields}&` : ""
    url += embed ? `embed=${embed}&` : ""

    core.debug(`url: ${url}`)

    return await utils.fcliRest(url)
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

    return (await utils.fcliRest(`/api/v1/projectVersions/${appId}/issues/action/updateTag`, "POST", JSON.stringify(body))).length > 0
}

export async function convertToAppVersion(vulns: any, appVersionId: string | number) {
    const targetVulns = await getAppVersionVulns(appVersionId, "", "id,issueInstanceId,revision")
    var jp = require('jsonpath')

    vulns.forEach(function (vuln: any, index: number, vulns: any[]) {
        const targetVuln = jp.query(targetVulns, `$..[?(@.issueInstanceId=="${vuln.issueInstanceId}")]`)[0]
        if (targetVuln.id) {
            vuln.id = targetVuln.id
            vuln.revision = targetVuln.revision
        } else {
            vulns.splice(index, 1)
        }
    })
}

export function getAuditVulnsRequest(appVersionId: string | number, vulns: any[], customTagAudits: any[]) {
    const body: any = {
        "issues": vulns,
        "customTagAudit": customTagAudits
    }

    const uri = `/api/v1/projectVersions/${appVersionId}/issues/action/audit`

    return {
        "httpVerb": "POST",
        "postData": body,
        "uri": core.getInput('ssc_base_url') + uri
    }
}

export async function auditVulns(appVersionId: string | number, vulns: any[], customTagAudits: any[]) {
    let body: any = {
        "issues": vulns,
        "customTagAudit": customTagAudits
    }

    core.debug(body)
    let {
        data: data,
        count: count,
        responseCode: responseCode,
        links: links
    } = await utils.fcliRest(`/api/v1/projectVersions/${appVersionId}/issues/action/audit`, "POST", JSON.stringify(body).replace("customTagIndex", "newCustomTagIndex"))
    core.debug(responseCode)

    if (200 <= Number(responseCode) && Number(responseCode) < 300) {
        return true
    } else {
        core.error(`AppVersion Commit failed with code ${responseCode}`)
        return false
    }

    return true
}