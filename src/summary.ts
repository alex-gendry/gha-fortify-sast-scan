import * as core from '@actions/core'
import * as vuln from './vuln'

export async function setJobSummary(app: string, version: string): Promise<any> {
    let vulns: any[] = await vuln.getAppVersionVulns(app, version)

    let table = []
    let headers: any[] = []
    let row: string[] = []

    vulns.forEach((element) => {
        headers.push({data: element["cleanName"], header: true})
        row.push(element["totalCount"])

    })

    core.debug(headers.toString())
    core.debug(row.toString())

    await core.summary
        .addHeading('Fortify SAST Results')
        // .addCodeBlock(generateTestResults(), "js")
        .addTable([
            // Headers
            headers,
            // rows
            row
        ])
        .addLink('View staging deployment!', 'https://github.com')
        .write()
}