import * as core from '@actions/core'
import * as vuln from './vuln'
import * as utils from "./utils";
import * as appversion from "./appversion";

function stringToHeader(element: string): string {
    switch (element) {
        case 'Critical':
            return `:red_circle: ${element}`
            break
        case 'High':
            return `:orange_circle: ${element}`
            break
        case 'Medium':
            return `:yellow_circle: ${element}`
            break
        case 'Low':
            return `:white_circle: ${element}`
            break
        default:
            return `:large_blue_circle: ${element}`
            break
    }
}

async function createVulnsByScanProductTable(appId: string|number): Promise<any> {

    const sastVulns = await vuln.getAppVersionVulnsCount(appId, "SAST")
    const dastVulns = await vuln.getAppVersionVulnsCount(appId, "DAST")
    const scaVulns = await vuln.getAppVersionVulnsCount(appId, "SCA")
    let table = []
    let headers: any[] = [{data: ':test_tube: Analysis Type', header: true}]
    let sastRow: any[] = ['SAST']
    let dastRow: any[] = ['DAST']
    let scaRow: any[] = ['SCA']

    sastVulns.forEach((element: any) => {
        headers.push({data: stringToHeader(element["cleanName"]), header: true})
        sastRow.push(`<p>${element["totalCount"]}</p>`)
    })
    dastVulns.forEach((element: any) => {
        dastRow.push(`<p>${element["totalCount"]}</p>`)
    })
    scaVulns.forEach((element: any) => {
        scaRow.push(`<p>${element["totalCount"]}</p>`)
    })

    return [
        // Headers
        headers,
        // rows
        sastRow,
        dastRow,
        scaRow
    ]

}

export async function setJobSummary(app: string, version: string): Promise<any> {
    const appId = await appversion.getAppVersionId(app, version)

    await core.summary
        .addImage('https://github.com/Andhrei/gha-fortify-sast-scan/blob/main/OpenTextBanner.png', 'Fortify by OpenText CyberSecurity')
        .addHeading('Fortify SAST Results')
        // .addCodeBlock(generateTestResults(), "js")
        .addTable(await createVulnsByScanProductTable(appId))
        .addLink('View staging deployment!', 'https://github.com')
        .write()
}