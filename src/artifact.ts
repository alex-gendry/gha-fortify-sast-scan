import * as utils from "./utils";

async function getAppVersionArtifacts(
    appId: string|number,
    scanType?: string, status:string|boolean="PROCESS_COMPLETE"): Promise<any> {
    let args = [
        'ssc',
        'appversion-artifact',
        'list',
        `--appversion=${appId}`,
        '--output=json'
    ]

    args = status
        ? args.concat([`-q=status=${status}`])
        : args
    args = scanType
        ? args.concat([`-q=scanTypes=${scanType}`])
        : args

    return await utils.fcli(args)
}
export async function getLatestSastArtifact(
    appId: string|number
): Promise<any> {
    let jsonRes = await getAppVersionArtifacts(appId,"SCA")

    return jsonRes[0]
}

export async function getLatestDastArtifact(
    appId: string|number
): Promise<any> {
    let jsonRes = await getAppVersionArtifacts(appId,"WEBINSPECT")

    return jsonRes[0]
}

export async function getLatestScaArtifact(
    appId: string|number
): Promise<any> {
    let jsonRes = await getAppVersionArtifacts(appId,"SONATYPE")

    return jsonRes[0]
}

