import * as utils from './utils'
import * as core from '@actions/core'

export async function packageSourceCode(buildOpts: string): Promise<number> {
  return await utils.scancentral(
    ['package'].concat(
      utils.stringToArgsArray(buildOpts).concat(['-o', 'package.zip'])
    )
  )
}

export async function startSastScan(app:string, version:string): Promise<string> {
  let jsonRes = await utils.fcli([
    'sc-sast',
    'scan',
    'start',
    '--upload',
    `--appversion=${app}:${version}`,
    `--sensor-version=23.1.0`,
    `--package-file=package.zip`,
    '--output=json'
  ])

  if (jsonRes.length === 0) {
    core.debug(`AppVersion "${app}":"${version}" not found`)
    return -1
  } else {
    core.debug(`AppVersion "${app}":"${version}" exists`)
    return jsonRes[0].id
  }
}