import * as core from '@actions/core'
import * as vuln from './vuln'
import * as appversion from "./appversion";
import * as filterset from "./filterset";
import * as artifact from "./artifact";

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

async function createVulnsByScanProductTable(appId: string | number, filterSet: string = "Security Auditor View"): Promise<any> {

    const sastVulns = await vuln.getAppVersionVulnsCount(appId, filterSet, "SAST")
    const dastVulns = await vuln.getAppVersionVulnsCount(appId, filterSet, "DAST")
    const scaVulns = await vuln.getAppVersionVulnsCount(appId, filterSet, "SCA")
    const totalVulns = await vuln.getAppVersionVulnsCount(appId, filterSet)
    const folders: any[] = await filterset.getFilterSetFolders(appId, filterSet)
    let table = []
    let headers: any[] = [{data: ':test_tube: Analysis Type', header: true}]
    var jp = require('jsonpath')
    let sastRow: any[] = ['SAST']
    let scaRow: any[] = ['DAST']
    let dastRow: any[] = ['SCA']
    let totalRow: any[] = ['Total']
    folders.forEach((folder) => {
        headers.push({data: stringToHeader(folder["name"]), header: true})
        const sastCount = jp.query(sastVulns, `$..[?(@.id=="${folder["name"]}")].totalCount`)[0]
        sastRow.push( sastCount ? `${sastCount}` : `${0}`)
        const dastCount = jp.query(dastVulns, `$..[?(@.id=="${folder["name"]}")].totalCount`)[0]
        dastRow.push( dastCount ? `${dastCount}` : `${0}`)
        const scaCount = jp.query(scaVulns, `$..[?(@.id=="${folder["name"]}")].totalCount`)[0]
        scaRow.push( scaCount ? `${scaCount}` : `${0}`)
        const totalCount = jp.query(totalVulns, `$..[?(@.id=="${folder["name"]}")].totalCount`)[0]
        totalRow.push( totalCount ? `${totalCount}` : `${0}`)
    })

    return [// Headers
        headers, // rows
        sastRow, dastRow, scaRow, totalRow]

}

// async function getAppSummaryTable(appId:string) {
//
// }

export async function setJobSummary(app: string, version: string): Promise<any> {
    const appId = await appversion.getAppVersionId(app, version)
    const lastSastScan = await artifact.getLatestSastArtifact(appId)
    const lastDastScan = await artifact.getLatestDastArtifact(appId)
    const lastScaScan = await artifact.getLatestScaArtifact(appId)

    await core.summary
        .addImage('https://cdn.asp.events/CLIENT_CloserSt_D86EA381_5056_B739_5482D50A1A831DDD/sites/CSWA-2023/media/libraries/exhibitors/Ezone-cover.png/fit-in/1500x9999/filters:no_upscale()', 'Fortify by OpenText CyberSecurity', {width: "600"})
        .addHeading('Fortify AST Results')
        .addHeading('Executive Summary', 2)
        .addTable([
            [`<b>Application</b>`, app, '', `<b>Last Successful SAST Scan</b>`,lastSastScan["lastScanDate"] ],
            [`<b>Application Version</b>`, version, '', `<b>Last Successful DAST Scan</b>`,lastDastScan["lastScanDate"] ],
            ['', '', '', `<b>Last Successful SAST Scan</b>`,lastSastScan["lastScanDate"] ]
        ])
        .addSeparator()
        .addRaw(`<table width="80%" cellspacing="0" cellpadding="5">
    <tbody>
    <tr>
        <td class="text">
            <table width="400" cellspacing="0">
                <tbody>
                <tr>
                    <td><b>Application Name</b></td>
                    <td>PetClinic</td>
                </tr>
                <tr>
                    <td><b>Application Version</b></td>
                    <td>1.0</td>
                </tr>
                </tbody>
            </table>

        <td>
            <table width="400" cellspacing="0">
                <tbody>
                <tr>
                    <td>Last SAST Scan</td>
                    <td>2023-04-18T09:02:19</td>
                </tr>
                <tr>
                    <td>Last DAST Scan</td>
                    <td>2023-04-18T09:02:19</td>
                </tr>
                <tr>
                    <td>Last SCA Scan</td>
                    <td>2023-04-18T09:02:19</td>
                </tr>
                </tbody>
            </table>
        </td>
    </tr>
    </tbody>
</table>`)
        .addHeading('Security Findings', 2)
        .addTable(await createVulnsByScanProductTable(appId,'Information'))
        .addLink('View staging deployment!', 'https://github.com')
        .write()
}