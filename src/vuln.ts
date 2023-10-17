import * as utils from './utils'
import * as core from '@actions/core'

export async function getAppVersionVulns(app: string, version: string): Promise<any> {
    let jsonRes = await utils.fcli([
        'ssc',
        'appversion-vuln',
        'count',
        `--appversion=${app}:${version}`,
        '--output=json'
    ])

    return jsonRes
}