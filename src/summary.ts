import * as core from '@actions/core'
import * as vuln from './vuln'
import * as appversion from "./appversion";
import * as filterset from "./filterset";
import * as artifact from "./artifact";
import * as utils from "./utils";
import * as performanceindicator from "./performanceindicator";

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

async function getVulnsByScanProductTable(appId: string | number, filterSet: string = "Security Auditor View"): Promise<any> {
    var jp = require('jsonpath')

    let headers: any[] = [{data: ':test_tube: Analysis Type', header: true}]
    let rows: any[] = []
    const scanTypesList: string[] = await artifact.getScanTypesList(appId)
    const folders: any[] = await filterset.getFilterSetFolders(appId, filterSet)

    folders.forEach((folder) => {
        headers.push({data: `${stringToHeader(folder["name"])}`, header: true})
    })
    headers.push({data: `Total`, header: true})

    await Promise.all(scanTypesList.map(async scanType => {
        let total: number = 0
        const vulns = await vuln.getAppVersionVulnsCount(appId, filterSet, scanType)
        let row: string[] = [`${utils.normalizeScanType(scanType)}`]

        folders.forEach((folder) => {
            const count = jp.query(vulns, `$..[?(@.id=="${folder["name"]}")].totalCount`)[0]
            row.push(count ? `${count}` : `${0}`)
            total += count
        })

        row.push(`${total}`)
        rows.push(row)
    }))

    return [headers].concat(rows)

}

async function getNewVulnsTable(appId: string | number, filterSet: string = "Security Auditor View"): Promise<any> {
    var jp = require('jsonpath')

    let headers: any[] = []
    let row: string[] = []
    let total: number = 0
    const folders: any[] = await filterset.getFilterSetFolders(appId, filterSet)
    const vulns = await vuln.getAppVersionNewVulnsCount(appId, filterSet)

    folders.forEach((folder) => {
        headers.push({data: `${stringToHeader(folder["name"])}`, header: true})
        const count = jp.query(vulns, `$..[?(@.id=="${folder["name"]}")].totalCount`)[0]
        row.push(count ? `${count}` : `${0}`)
        total += count
    })

    headers.push({data: `Total`, header: true})
    row.push(`${total}`)

    return [
        headers,
        row
    ]
}

async function getScansSummaryTable(appId: string | number): Promise<any[]> {
    const scanTypesList: string[] = await artifact.getScanTypesList(appId)
    let scanRows: any[] = []

    await Promise.all(
        scanTypesList.map(async scanType => {
            const lastScan = await artifact.getLatestArtifact(appId, scanType)
            const lastDate = new Date(lastScan["lastScanDate"])
            const diffDays = Math.ceil(Math.abs(new Date().getDate() - lastDate.getDate()) / (1000 * 60 * 60 * 24));
            scanRows.push([`<b>Last Successful ${utils.normalizeScanType(scanType)} Scan</b>`, `${lastDate.toLocaleString('fr-FR')} (${diffDays} days ago)`])
        })
    )

    return scanRows
}

export async function setJobSummary(app: string, version: string, base_url: string): Promise<any> {
    const appId = await appversion.getAppVersionId(app, version)

    const securityRating = await performanceindicator.getPerformanceIndicatorValueByName(appId, 'Fortify Security Rating')
    let n = 0
    const securityStars: string = ":white_circle::white_circle::white_circle::white_circle::white_circle:".replace(/white_circle/g, match => n++ < securityRating ? "star" : match)

    const appVersionURL: string = `${base_url}/html/ssc/version/${appId}/audit`

    await core.summary
        .addImage('https://cdn.asp.events/CLIENT_CloserSt_D86EA381_5056_B739_5482D50A1A831DDD/sites/CSWA-2023/media/libraries/exhibitors/Ezone-cover.png/fit-in/1500x9999/filters:no_upscale()', 'Fortify by OpenText CyberSecurity', {width: "600"})
        .addHeading('Fortify AST Results')
        .addHeading('Executive Summary', 2)
        .addTable([[`<b>Application</b>`, app, `<b>Application Version</b>`, `${version}`]])
        .addRaw(` [:link:](${appVersionURL})`)
        .addTable([[`<p><b>Fortify Security Rating</b>:   ${securityStars}</p>`]])
        .addTable(await getScansSummaryTable(appId))
        .addHeading('Security Findings', 2)
        .addHeading(':new: Newly Added Security Findings', 2)
        .addTable(await getNewVulnsTable(appId, 'Security Auditor View'))
        .addHeading(':signal_strength: All Security Findings', 2)
        .addTable(await getVulnsByScanProductTable(appId, 'Security Auditor View'))
        .addLink('View staging deployment!', 'https://github.com')
        .write()
}