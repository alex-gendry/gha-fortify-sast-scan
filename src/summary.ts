import * as core from '@actions/core'
import * as vuln from './vuln'

export async function setJobSummary(app: string, version: string): Promise<any> {
    let vulns: any[] = await vuln.getAppVersionVulns(app, version)

    let table = []
    let headers: any[] = []
    let row: string[] = []

    vulns.forEach((element) => {
        switch (element["cleanName"]) {
            case 'Critical':
                headers.push({data: `:red_circle: element["cleanName"]`, header: true})
                break
            case 'High':
                headers.push({data: `:orange_circle: element["cleanName"]`, header: true})
                break
            case 'Medium':
                headers.push({data: `:yellow_circle: element["cleanName"]`, header: true})
                break
            case 'Low':
                headers.push({data: `:white_circle: element["cleanName"]`, header: true})
                break
            default:
                headers.push({data: `:large_blue_circle: element["cleanName"]`, header: true})
                break
        }
        row.push(`<p>${element["totalCount"]}</p>`)

    })

    core.debug(headers.toString())
    core.debug(row.toString())

    await core.summary
        .addImage('https://github.com/Andhrei/gha-fortify-sast-scan/blob/main/OpenTextBanner.png', 'Fortify by OpenText CyberSecurity')
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