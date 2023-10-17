import * as utils from "./utils";

export async function getFilterSetGuid(
    appId: string|number,
    filterSetName: string
): Promise<any> {
    let jsonRes = await utils.fcli([
        'ssc',
        'appversion-filterset',
        'get',
        filterSetName,
        `--appversion=${appId}`,
        '--output=json'
    ])

    return jsonRes["guid"]
}

export async function getFilterSetFolders(
    appId: string|number,
    filterSetName: string
): Promise<any> {
    let jsonRes = await utils.fcli([
        'ssc',
        'appversion-filterset',
        'get',
        filterSetName,
        `--appversion=${appId}`,
        '--output=json'
    ])

    return jsonRes["folders"]
}
