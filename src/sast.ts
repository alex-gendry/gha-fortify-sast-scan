import * as utils from './utils'
import * as core from '@actions/core'

export async function packageSourceCode(buildOpts: string, packagePath : string): Promise<number> {
    return await utils.scancentral(
        ['package'].concat(
            utils.stringToArgsArray(buildOpts).concat(['-o', packagePath])
        )
    )
}

export async function startSastScan(packagePath : string): Promise<string> {
    let jsonRes = await utils.fcli([
        'sc-sast',
        'scan',
        'start',
        // '--upload',
        // `--appversion=${app}:${version}`,
        `--sensor-version=23.1.0`,
        `--package-file=${packagePath}`,
        '--output=json'
    ])

    if (jsonRes['__action__'] == 'SCAN_REQUESTED') {
        core.debug(`Scan ${jsonRes['jobToken']} requested`)
        return jsonRes['jobToken']
    } else {
        throw new Error(
            `Scan submission failed: Fortify returned ${jsonRes['__action__']}`
        )
    }
}

export async function waitForSastScan(jobToken: string): Promise<boolean> {
    let scanStatus = await utils.fcli(
        ['sc-sast', 'scan', 'wait-for', jobToken, `--status-type=scan`, `--while-any=PENDING,QUEUED,RUNNING`, `--interval=1m`],
        true, false
    )
    let jsonRes = await utils.fcli(
        ['sc-sast', 'scan', 'wait-for', jobToken, `--interval=1m`, `--status-type=scan`, `--while-any=PENDING,QUEUED,RUNNING`, '--no-progress', '--output=json']
    )

    jsonRes = jsonRes[0]

    if (
        jsonRes['scanState'] === 'COMPLETED' &&
        jsonRes['sscUploadState'] === 'COMPLETED' &&
        jsonRes['sscArtifactState'] === 'PROCESS_COMPLETE'
    ) {
        core.debug(`Scan ${jsonRes['jobToken']} COMPLETED`)
        return true
    } else if (jsonRes['scanState'] != 'COMPLETED') {
        throw new Error(
            `Scan execution failed: Fortify returned scanState=${jsonRes['scanState']}`
        )
    } else if (jsonRes['sscUploadState'] != 'COMPLETED') {
        throw new Error(
            `Scan upload failed: Fortify returned sscUploadState=${jsonRes['scanState']}`
        )
    } else if (jsonRes['sscArtifactState'] != 'PROCESS_COMPLETE') {
        throw new Error(
            `Scan artifact processing failed: Fortify returned sscArtifactState=${jsonRes['scanState']}`
        )
    } else {
        throw new Error(`Scan failed: Fortify returned ${jsonRes['__action__']}`)
    }

    return false
}
