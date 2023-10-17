import * as core from '@actions/core'
import * as vuln from './vuln'
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

async function createVulnsByScanProductTable(appId: string | number): Promise<any> {

    const sastVulns = await vuln.getAppVersionVulnsCount(appId, "SAST")
    const dastVulns = await vuln.getAppVersionVulnsCount(appId, "DAST")
    const scaVulns = await vuln.getAppVersionVulnsCount(appId, "SCA")
    const totalVulns = await vuln.getAppVersionVulnsCount(appId)
    let table = []
    var jp = require('jsonpath')
    let headers: any[] = [{data: ':test_tube: Analysis Type', header: true},
        {data: stringToHeader('Critical'), header: true},
        {data: stringToHeader('High'), header: true},
        {data: stringToHeader('Medium'), header: true},
        {data: stringToHeader('Low'), header: true}]
    let sastRow: any[] = [
        '**SAST**',
        jp.query(sastVulns, '$..[?(@.id=="Critical")].totalCount')[0] ? jp.query(sastVulns, '$..[?(@.id=="Critical")].totalCount')[0] : 0 ,
        jp.query(sastVulns, '$..[?(@.id=="High")].totalCount')[0] ? jp.query(sastVulns, '$..[?(@.id=="High")].totalCount')[0] : 0,
        jp.query(sastVulns, '$..[?(@.id=="Medium")].totalCount')[0] ? jp.query(sastVulns, '$..[?(@.id=="Medium")].totalCount')[0] : 0,
        jp.query(sastVulns, '$..[?(@.id=="Low")].totalCount')[0] ? jp.query(sastVulns, '$..[?(@.id=="Low")].totalCount')[0] : 0]
    let dastRow: any[] = [
        '**DAST**',
        jp.query(dastVulns, '$..[?(@.id=="Critical")].totalCount')[0] ? jp.query(dastVulns, '$..[?(@.id=="Critical")].totalCount')[0] : 0 ,
        jp.query(dastVulns, '$..[?(@.id=="High")].totalCount')[0] ? jp.query(dastVulns, '$..[?(@.id=="High")].totalCount')[0] : 0,
        jp.query(dastVulns, '$..[?(@.id=="Medium")].totalCount')[0] ? jp.query(dastVulns, '$..[?(@.id=="Medium")].totalCount')[0] : 0,
        jp.query(dastVulns, '$..[?(@.id=="Low")].totalCount')[0] ? jp.query(dastVulns, '$..[?(@.id=="Low")].totalCount')[0] : 0]
    let scaRow: any[] = ['**SCA**',
        jp.query(scaVulns, '$..[?(@.id=="Critical")].totalCount')[0] ? jp.query(scaVulns, '$..[?(@.id=="Critical")].totalCount')[0] : 0 ,
        jp.query(scaVulns, '$..[?(@.id=="High")].totalCount')[0] ? jp.query(scaVulns, '$..[?(@.id=="High")].totalCount')[0] : 0,
        jp.query(scaVulns, '$..[?(@.id=="Medium")].totalCount')[0] ? jp.query(scaVulns, '$..[?(@.id=="Medium")].totalCount')[0] : 0,
        jp.query(scaVulns, '$..[?(@.id=="Low")].totalCount')[0] ? jp.query(scaVulns, '$..[?(@.id=="Low")].totalCount')[0] : 0]
    let totalRow: any[] = ['**Total**',
        jp.query(totalVulns, '$..[?(@.id=="Critical")].totalCount')[0] ? jp.query(totalVulns, '$..[?(@.id=="Critical")].totalCount')[0] : 0 ,
        jp.query(totalVulns, '$..[?(@.id=="High")].totalCount')[0] ? jp.query(totalVulns, '$..[?(@.id=="High")].totalCount')[0] : 0,
        jp.query(totalVulns, '$..[?(@.id=="Medium")].totalCount')[0] ? jp.query(totalVulns, '$..[?(@.id=="Medium")].totalCount')[0] : 0,
        jp.query(totalVulns, '$..[?(@.id=="Low")].totalCount')[0] ? jp.query(totalVulns, '$..[?(@.id=="Low")].totalCount')[0] : 0]

    core.debug(totalRow.toString())

    return [// Headers
        headers, // rows
        sastRow, dastRow, scaRow]

}

export async function setJobSummary(app: string, version: string): Promise<any> {
    const appId = await appversion.getAppVersionId(app, version)

    await core.summary
        .addImage('https://github.com/Andhrei/gha-fortify-sast-scan/blob/main/OpenTextBanner.png', 'Fortify by OpenText CyberSecurity')
        .addHeading('Fortify AST Results')
        // .addCodeBlock(generateTestResults(), "js")
        .addTable(await createVulnsByScanProductTable(appId))
        .addLink('View staging deployment!', 'https://github.com')
        .write()
}